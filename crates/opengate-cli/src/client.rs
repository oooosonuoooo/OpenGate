use anyhow::{Context, Result, bail, ensure};
use opengate_protocol::*;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

pub async fn rpc(dir: &Path, command: LocalCommand) -> Result<Reply> {
    let mut stream = local_stream(dir, command).await?;
    let reply: Reply =
        tokio::time::timeout(Duration::from_secs(90), read_frame(&mut stream)).await??;
    reply.check()?;
    Ok(reply)
}

async fn local_stream(dir: &Path, command: LocalCommand) -> Result<TcpStream> {
    let endpoint = ensure_daemon(dir).await?;
    let mut stream = TcpStream::connect(&endpoint.address).await?;
    write_frame(
        &mut stream,
        &LocalRequest {
            auth: endpoint.secret,
            command,
        },
    )
    .await?;
    Ok(stream)
}

pub async fn open(dir: &Path, device: &str, request: RemoteRequest) -> Result<TcpStream> {
    let mut stream = local_stream(
        dir,
        LocalCommand::Open {
            device: device.into(),
            request,
        },
    )
    .await?;
    let reply: Reply =
        tokio::time::timeout(Duration::from_secs(90), read_frame(&mut stream)).await??;
    reply.check()?;
    Ok(stream)
}

pub async fn ensure_daemon(dir: &Path) -> Result<crate::daemon::Endpoint> {
    if let Ok(endpoint) = crate::daemon::endpoint(dir)
        && tokio::time::timeout(
            Duration::from_millis(300),
            TcpStream::connect(&endpoint.address),
        )
        .await
        .is_ok_and(|r| r.is_ok())
    {
        return Ok(endpoint);
    }
    opengate_security::Identity::load_or_create(dir)?;
    let executable = std::env::current_exe()?;
    let mut command = tokio::process::Command::new(executable);
    command
        .arg("--data-dir")
        .arg(dir)
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("daemon.log"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        log.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    command.stderr(Stdio::from(log));
    #[cfg(windows)]
    {
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().context("unable to start OpenGate daemon")?;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(endpoint) = crate::daemon::endpoint(dir)
            && tokio::time::timeout(
                Duration::from_millis(100),
                TcpStream::connect(&endpoint.address),
            )
            .await
            .is_ok_and(|r| r.is_ok())
        {
            return Ok(endpoint);
        }
        if let Some(status) = child.try_wait()? {
            bail!(
                "daemon exited ({status}); inspect {}/daemon.log",
                dir.display()
            );
        }
    }
    bail!(
        "daemon startup timed out; inspect {}/daemon.log",
        dir.display()
    )
}

pub async fn shell(
    dir: &Path,
    device: &str,
    mut request: ShellRequest,
    command: Option<String>,
) -> Result<()> {
    if let Ok((cols, rows)) = crossterm::terminal::size() {
        request.cols = cols;
        request.rows = rows;
    }
    let mut stream = open(dir, device, RemoteRequest::Shell(request.clone())).await?;
    if let Some(command) = command {
        write_frame(
            &mut stream,
            &TerminalFrame::Input(format!("{command}\nexit\n").into_bytes()),
        )
        .await?;
        loop {
            match read_frame(&mut stream).await? {
                TerminalFrame::Output(data) => {
                    use std::io::Write;
                    std::io::stdout().write_all(&data)?;
                    std::io::stdout().flush()?;
                }
                TerminalFrame::Exit { code } => {
                    ensure!(code == 0, "remote shell exited with code {code}");
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    } else {
        eprintln!("OpenGate Secure Shell — encrypted, authenticated: {device}");
        opengate_terminal::client(stream, request).await
    }
}

pub async fn file_request(dir: &Path, device: &str, request: FileRequest) -> Result<FileReply> {
    let stream = open(dir, device, RemoteRequest::Files).await?;
    let reply = opengate_files::request(stream, request).await?;
    if let FileReply::Error(message) = &reply {
        bail!("{message}");
    }
    Ok(reply)
}

pub async fn transfer(
    dir: &Path,
    device: &str,
    source: &str,
    destination: &str,
    push: bool,
    overwrite: bool,
    resume: bool,
) -> Result<()> {
    // Directory recursion uses separate streams per file; never buffers the tree contents.
    if push && Path::new(source).is_dir() {
        file_request(
            dir,
            device,
            FileRequest::Mkdir {
                path: destination.into(),
            },
        )
        .await?;
        let mut pending = vec![(PathBuf::from(source), destination.to_string())];
        while let Some((local, remote)) = pending.pop() {
            let mut entries = tokio::fs::read_dir(local).await?;
            while let Some(entry) = entries.next_entry().await? {
                let kind = entry.file_type().await?;
                ensure!(
                    !kind.is_symlink(),
                    "directory upload does not follow symlinks"
                );
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("filename is not UTF-8"))?;
                let target = format!("{}/{name}", remote.trim_end_matches('/'));
                if kind.is_dir() {
                    file_request(
                        dir,
                        device,
                        FileRequest::Mkdir {
                            path: target.clone(),
                        },
                    )
                    .await?;
                    pending.push((entry.path(), target));
                } else if kind.is_file() {
                    transfer_file(
                        dir,
                        device,
                        &entry.path().to_string_lossy(),
                        &target,
                        true,
                        overwrite,
                        resume,
                    )
                    .await?;
                }
            }
        }
        return Ok(());
    }
    if !push {
        let metadata = file_request(
            dir,
            device,
            FileRequest::Stat {
                path: source.into(),
            },
        )
        .await?;
        if matches!(metadata,FileReply::Metadata(ref entry) if entry.is_dir) {
            tokio::fs::create_dir_all(destination).await?;
            let mut pending = vec![(source.to_string(), PathBuf::from(destination))];
            while let Some((remote, local)) = pending.pop() {
                let FileReply::Entries(entries) = file_request(
                    dir,
                    device,
                    FileRequest::List {
                        path: remote.clone(),
                    },
                )
                .await?
                else {
                    bail!("invalid directory listing")
                };
                for entry in entries {
                    // A remote peer cannot write paths outside the selected download tree.
                    ensure!(
                        !entry.name.is_empty()
                            && entry.name != "."
                            && entry.name != ".."
                            && !entry.name.contains(['/', '\\', ':'])
                            && !entry.name.chars().any(char::is_control),
                        "unsafe remote filename"
                    );
                    let source =
                        format!("{}/{name}", remote.trim_end_matches('/'), name = entry.name);
                    let target = local.join(entry.name);
                    ensure!(!target.is_symlink(), "refusing local destination symlink");
                    if entry.is_dir {
                        tokio::fs::create_dir_all(&target).await?;
                        pending.push((source, target));
                    } else {
                        transfer_file(
                            dir,
                            device,
                            &source,
                            &target.to_string_lossy(),
                            false,
                            overwrite,
                            resume,
                        )
                        .await?;
                    }
                }
            }
            return Ok(());
        }
    }
    transfer_file(dir, device, source, destination, push, overwrite, resume).await
}

async fn transfer_file(
    dir: &Path,
    device: &str,
    source: &str,
    destination: &str,
    push: bool,
    overwrite: bool,
    resume: bool,
) -> Result<()> {
    let mut retry = 0usize;
    loop {
        let result = async {
            let stream = open(dir, device, RemoteRequest::Files).await?;
            transfer_stream(stream, source, destination, push, overwrite).await
        }
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(error) => {
                let transient = Reply::from_error(&error).retryable;
                // Authorization, path and checksum errors are terminal; commands are never replayed.
                if !resume || !transient {
                    return Err(error);
                }
                let seconds = [1, 2, 4, 8, 15, 30, 60][retry.min(6)];
                retry += 1;
                eprintln!(
                    "Transfer interrupted; reconnecting in {seconds}s. Verified partial data will be resumed."
                );
                tokio::select! {_=tokio::time::sleep(Duration::from_secs(seconds))=>{},_=tokio::signal::ctrl_c()=>bail!("transfer cancelled; checkpoint retained")}
            }
        }
    }
}

async fn transfer_stream(
    stream: TcpStream,
    source: &str,
    destination: &str,
    push: bool,
    overwrite: bool,
) -> Result<()> {
    let cancel = CancellationToken::new();
    let direction = if push { "Uploading" } else { "Downloading" };
    let mut reporter = ProgressReporter::new(direction);
    let transfer = async {
        if push {
            opengate_files::push_with_progress(
                stream,
                Path::new(source),
                destination,
                overwrite,
                cancel.clone(),
                |progress| reporter.report(progress),
            )
            .await
        } else {
            opengate_files::pull_with_progress(
                stream,
                source,
                Path::new(destination),
                overwrite,
                cancel.clone(),
                |progress| reporter.report(progress),
            )
            .await
        }
    };
    tokio::select! {
        result = transfer => {
            result?;
            reporter.complete();
            Ok(())
        }
        _ = tokio::signal::ctrl_c() => {
            cancel.cancel();
            bail!("transfer cancelled; durable checkpoint retained")
        }
    }
}

struct ProgressReporter {
    direction: &'static str,
    started: Instant,
    last_render: Instant,
    last: opengate_files::TransferProgress,
}

impl ProgressReporter {
    fn new(direction: &'static str) -> Self {
        let now = Instant::now();
        Self {
            direction,
            started: now,
            last_render: now.checked_sub(Duration::from_secs(1)).unwrap_or(now),
            last: opengate_files::TransferProgress {
                transferred: 0,
                total: 0,
            },
        }
    }

    fn report(&mut self, progress: opengate_files::TransferProgress) {
        self.last = progress;
        let now = Instant::now();
        if progress.transferred != progress.total
            && now.duration_since(self.last_render) < Duration::from_millis(250)
        {
            return;
        }
        self.last_render = now;
        let elapsed = now.duration_since(self.started).as_secs_f64().max(0.001);
        let percent = if progress.total == 0 {
            100.0
        } else {
            progress.transferred as f64 * 100.0 / progress.total as f64
        };
        eprint!(
            "\r{}: {}/{} ({percent:.1}%) · {}/s",
            self.direction,
            human_bytes(progress.transferred),
            human_bytes(progress.total),
            human_bytes((progress.transferred as f64 / elapsed) as u64),
        );
    }

    fn complete(&self) {
        eprintln!(
            "\r{}: {}/{} (100.0%) · complete",
            self.direction,
            human_bytes(self.last.transferred),
            human_bytes(self.last.total),
        );
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn bind_address(value: &str, allow_public: bool) -> Result<std::net::SocketAddr> {
    let address = if let Ok(port) = value.parse::<u16>() {
        std::net::SocketAddr::from(([127, 0, 0, 1], port))
    } else {
        value.parse()?
    };
    ensure!(
        address.ip().is_loopback() || allow_public,
        "public proxy bind requires --acknowledge-public-bind"
    );
    Ok(address)
}

pub struct ForwardOptions {
    pub local: String,
    pub remote: String,
    pub desktop: bool,
    pub allow_public: bool,
    pub socks: bool,
    pub launch_desktop: bool,
}

pub async fn forward(dir: PathBuf, device: String, options: ForwardOptions) -> Result<()> {
    let ForwardOptions {
        local,
        remote,
        desktop,
        allow_public,
        socks,
        launch_desktop,
    } = options;
    let address = bind_address(&local, allow_public)?;
    let listener = TcpListener::bind(address).await?;
    let ready_address = listener.local_addr()?;
    eprintln!(
        "OpenGate {} listening on {} → {} {}",
        if socks {
            "SOCKS5"
        } else if desktop {
            "desktop tunnel"
        } else {
            "TCP tunnel"
        },
        ready_address,
        device,
        remote
    );
    if desktop && launch_desktop {
        launch_desktop_client(ready_address, &remote)?;
    } else if desktop {
        eprintln!(
            "Tunnel is ready. Connect your RDP/VNC client to {ready_address}, or add --launch to start a detected client."
        );
    }
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(64));
    let mut sessions = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            Some(_)=sessions.join_next()=>{},
            accepted=listener.accept()=> {
                let (mut local,_)=accepted?;
                let Ok(permit)=limit.clone().try_acquire_owned() else {continue};
                let dir=dir.clone();let device=device.clone();let target=remote.clone();
                sessions.spawn(async move {
                    let _permit=permit;
                    let result:Result<()>=async {
                        let target=if socks {tokio::time::timeout(Duration::from_secs(10),opengate_tunnel::negotiate(&mut local)).await??} else {target};
                        match open(&dir,&device,RemoteRequest::Tunnel{target,desktop}).await {
                            Ok(mut remote)=>{if socks {opengate_tunnel::reply(&mut local,true).await?;}tokio::io::copy_bidirectional(&mut local,&mut remote).await?;},
                            Err(error)=>{if socks {let _=opengate_tunnel::reply(&mut local,false).await;}return Err(error);},
                        }Ok(())
                    }.await;
                    if let Err(error)=result {eprintln!("Tunnel connection ended: {error}");}
                });
            }
        }
    }
    sessions.abort_all();
    Ok(())
}

fn program_in_path(names: &[&str]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .flat_map(|directory| names.iter().map(move |name| directory.join(name)))
        .find(|candidate| candidate.is_file())
}

fn launch_desktop_client(address: std::net::SocketAddr, remote: &str) -> Result<()> {
    let vnc = remote.ends_with(":5900");
    #[cfg(windows)]
    let command = if vnc {
        program_in_path(&["vncviewer.exe", "vncviewer"]).map(|program| {
            let mut command = tokio::process::Command::new(program);
            command.arg(address.to_string());
            command
        })
    } else {
        program_in_path(&["mstsc.exe", "mstsc"]).map(|program| {
            let mut command = tokio::process::Command::new(program);
            command.arg(format!("/v:{address}"));
            command
        })
    };
    #[cfg(not(windows))]
    let command = if vnc {
        program_in_path(&["vncviewer", "xtigervncviewer"]).map(|program| {
            let mut command = tokio::process::Command::new(program);
            command.arg(address.to_string());
            command
        })
    } else {
        program_in_path(&["xfreerdp", "xfreerdp3"]).map(|program| {
            let mut command = tokio::process::Command::new(program);
            command.arg(format!("/v:{address}"));
            command
        })
    };
    let mut command = command.context(if vnc {
        "no supported VNC client was found in PATH; connect manually to the ready tunnel"
    } else {
        "no supported RDP client was found in PATH; connect manually to the ready tunnel"
    })?;
    command
        .spawn()
        .context("starting the local desktop client")?;
    eprintln!(
        "Started the local {} client for {address}.",
        if vnc { "VNC" } else { "RDP" }
    );
    Ok(())
}

/// Sample actual application byte counters; expose rates with their measurement
/// interval so callers do not mistake cumulative totals for current throughput.
pub async fn network_status(dir: &Path) -> Result<serde_json::Value> {
    let before = rpc(dir, LocalCommand::Status).await?.data;
    let started = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let mut after = rpc(dir, LocalCommand::Status).await?.data;
    let seconds = started.elapsed().as_secs_f64();
    if let Some(peers) = after["traffic"].as_array_mut() {
        for peer in peers {
            let prior = before["traffic"]
                .as_array()
                .and_then(|rows| rows.iter().find(|row| row["peer_id"] == peer["peer_id"]));
            for (counter, rate) in [
                ("sent_bytes", "upload_bytes_per_second"),
                ("received_bytes", "download_bytes_per_second"),
            ] {
                let current = peer[counter].as_u64().unwrap_or(0);
                let previous = prior.and_then(|row| row[counter].as_u64()).unwrap_or(0);
                peer[rate] = serde_json::json!(current.saturating_sub(previous) as f64 / seconds);
            }
        }
    }
    after["measurement_seconds"] = serde_json::json!(seconds);
    after["traffic_scope"] =
        serde_json::json!("authenticated application streams; transport overhead excluded");
    Ok(after)
}

#[cfg(test)]
mod tests {
    use super::{bind_address, human_bytes};

    #[test]
    fn desktop_and_forward_defaults_remain_loopback_only() {
        assert_eq!(
            bind_address("13389", false).unwrap().to_string(),
            "127.0.0.1:13389"
        );
        assert!(bind_address("0.0.0.0:13389", false).is_err());
    }

    #[test]
    fn transfer_progress_uses_readable_units() {
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
    }
}
