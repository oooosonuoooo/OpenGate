//! Acceptance checks use real daemon processes, persistent state and libp2p streams.
use anyhow::{Context, Result, ensure};
use opengate_protocol::*;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Deserialize)]
struct Endpoint {
    address: String,
    secret: String,
}
struct Daemon {
    child: Child,
    dir: PathBuf,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Daemon {
    async fn start(dir: &Path, port: Option<u16>) -> Result<Self> {
        let listen = format!("/ip4/127.0.0.1/udp/{}/quic-v1", port.unwrap_or(0));
        let child = Command::new(env!("CARGO_BIN_EXE_opengate"))
            .arg("--data-dir")
            .arg(dir)
            .arg("daemon")
            .arg("--listen")
            .arg(listen)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut daemon = Self {
            child,
            dir: dir.to_owned(),
        };
        for _ in 0..150 {
            if let Some(status) = daemon.child.try_wait()? {
                anyhow::bail!("test daemon exited: {status}");
            }
            if let Ok(reply) = daemon.rpc(LocalCommand::Status).await
                && reply.ok
                && reply.data["network"]["listeners"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty())
            {
                return Ok(daemon);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!("test daemon startup timeout")
    }
    fn endpoint(&self) -> Result<Endpoint> {
        Ok(serde_json::from_slice(&opengate_security::secure_read(
            &self.dir.join("daemon.endpoint"),
        )?)?)
    }
    async fn request(&self, command: LocalCommand) -> Result<TcpStream> {
        let endpoint = self.endpoint()?;
        let mut stream = TcpStream::connect(endpoint.address).await?;
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
    async fn rpc(&self, command: LocalCommand) -> Result<Reply> {
        let mut stream = self.request(command).await?;
        tokio::time::timeout(Duration::from_secs(60), read_frame(&mut stream))
            .await
            .context("local RPC timeout")?
    }
    async fn ok(&self, command: LocalCommand) -> Result<serde_json::Value> {
        let reply = self.rpc(command).await?;
        reply.check()?;
        Ok(reply.data)
    }
    async fn open(&self, device: &str, request: RemoteRequest) -> Result<TcpStream> {
        let mut stream = self
            .request(LocalCommand::Open {
                device: device.into(),
                request,
            })
            .await?;
        let reply: Reply =
            tokio::time::timeout(Duration::from_secs(60), read_frame(&mut stream)).await??;
        reply.check()?;
        Ok(stream)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pair_shell_files_forward_restart_and_revoke() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let a = Daemon::start(&temp.path().join("a"), None).await?;
    let mut b = Daemon::start(&temp.path().join("b"), None).await?;
    a.ok(LocalCommand::ConfigSet {
        key: "name".into(),
        value: "CLIENT-A".into(),
    })
    .await?;
    b.ok(LocalCommand::ConfigSet {
        key: "name".into(),
        value: "HOST-B".into(),
    })
    .await?;
    // Safe for CI running as root: explicit dual owner opt-in; isolated temporary state only.
    #[cfg(unix)]
    let root = unsafe { libc::geteuid() == 0 };
    #[cfg(not(unix))]
    let root = opengate_service::is_elevated();
    let permissions = if root {
        a.ok(LocalCommand::ConfigSet {
            key: "allow_admin".into(),
            value: "true".into(),
        })
        .await?;
        b.ok(LocalCommand::ConfigSet {
            key: "allow_admin".into(),
            value: "true".into(),
        })
        .await?;
        Permissions::full_admin()
    } else {
        Permissions::standard()
    };
    let allowed = b
        .ok(LocalCommand::Allow {
            permissions: permissions.clone(),
            ttl: 900,
        })
        .await?;
    let token = allowed["token"].as_str().context("token")?.to_owned();
    let paired = a
        .ok(LocalCommand::Pair {
            token: token.clone(),
            grant: permissions.clone(),
        })
        .await?;
    let b_id = paired["device"]["peer_id"]
        .as_str()
        .context("peer id")?
        .to_owned();
    let a_id = a.ok(LocalCommand::Status).await?["device"]["peer_id"]
        .as_str()
        .context("peer id")?
        .to_owned();
    ensure!(
        !a.rpc(LocalCommand::Pair {
            token,
            grant: permissions.clone()
        })
        .await?
        .ok,
        "used token accepted twice"
    );
    for (daemon, device) in [(&a, &b_id), (&b, &a_id)] {
        daemon
            .ok(LocalCommand::ConnectionPreferences {
                device: device.clone(),
                auto_reconnect: Some(false),
                connection_timeout_seconds: Some(5),
            })
            .await?;
    }
    let authenticated = a
        .ok(LocalCommand::Connect {
            device: b_id.clone(),
        })
        .await?;
    ensure!(
        authenticated["device"]["protocol_version"] == VERSION,
        "remote protocol version missing"
    );
    ensure!(
        authenticated["device"]["app_version"] == env!("CARGO_PKG_VERSION"),
        "remote application version missing"
    );
    for (daemon, device) in [(&a, &b_id), (&b, &a_id)] {
        let status = daemon.ok(LocalCommand::Status).await?;
        ensure!(
            !status["network"]["peers"]
                .as_array()
                .context("tracked peers")?
                .iter()
                .any(|p| p["peer_id"] == *device),
            "manual authentication re-enabled disabled background reconnect"
        );
        let connection = status["network"]["connections"]
            .as_array()
            .context("connections")?
            .iter()
            .find(|p| p["peer_id"] == *device)
            .context("missing connected peer")?;
        ensure!(
            connection["encrypted"] == true
                && connection["authenticated"] == true
                && connection["transport"] == "QUIC",
            "connection security display missing"
        );
        daemon
            .ok(LocalCommand::ConnectionPreferences {
                device: device.clone(),
                auto_reconnect: Some(true),
                connection_timeout_seconds: Some(30),
            })
            .await?;
    }
    // Interactive programs run through a PTY, not a pre-canned command response.
    let mut shell = a
        .open(&b_id, RemoteRequest::Shell(ShellRequest::default()))
        .await?;
    write_frame(
        &mut shell,
        &TerminalFrame::Resize {
            rows: 35,
            cols: 100,
        },
    )
    .await?;
    #[cfg(windows)]
    let command = b"echo OPENGATE_PTY_VERIFIED\r\nexit\r\n".to_vec();
    #[cfg(not(windows))]
    let command = b"printf 'OPENGATE_PTY_VERIFIED\\n'\nexit\n".to_vec();
    write_frame(&mut shell, &TerminalFrame::Input(command)).await?;
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match read_frame::<TerminalFrame, _>(&mut shell).await? {
                TerminalFrame::Output(bytes) => output.extend(bytes),
                TerminalFrame::Exit { code } => {
                    let _ = code;
                    break;
                }
                _ => {}
            }
        }
        anyhow::Ok(())
    })
    .await??;
    ensure!(
        String::from_utf8_lossy(&output).contains("OPENGATE_PTY_VERIFIED"),
        "PTY output missing"
    );
    // Multi-chunk push and pull over independent authenticated streams.
    let original = temp.path().join("source.bin");
    let received = temp.path().join("received.bin");
    let data: Vec<u8> = (0..1_048_577).map(|i| (i % 251) as u8).collect();
    tokio::fs::write(&original, &data).await?;
    opengate_files::push(
        a.open(&b_id, RemoteRequest::Files).await?,
        &original,
        "payload.bin",
        false,
    )
    .await?;
    opengate_files::pull(
        a.open(&b_id, RemoteRequest::Files).await?,
        "payload.bin",
        &received,
        false,
    )
    .await?;
    ensure!(
        tokio::fs::read(&received).await? == data,
        "file integrity mismatch"
    );
    let denied = opengate_files::request(
        a.open(&b_id, RemoteRequest::Files).await?,
        FileRequest::Stat {
            path: "../identity.key".into(),
        },
    )
    .await;
    ensure!(
        denied.is_err() || matches!(denied?, FileReply::Error(_)),
        "file traversal accepted"
    );
    // Real TCP service through encrypted peer transport.
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let target = echo.local_addr()?.to_string();
    let echo_task = tokio::spawn(async move {
        let (mut socket, _) = echo.accept().await?;
        let mut data = [0u8; 8];
        socket.read_exact(&mut data).await?;
        socket.write_all(&data).await?;
        tokio::time::sleep(Duration::from_secs(60)).await;
        anyhow::Ok(())
    });
    let mut tunnel = a
        .open(
            &b_id,
            RemoteRequest::Tunnel {
                target,
                desktop: false,
            },
        )
        .await?;
    tunnel.write_all(b"OG-ECHO!").await?;
    let mut echoed = [0; 8];
    tokio::time::timeout(Duration::from_secs(10), tunnel.read_exact(&mut echoed)).await??;
    ensure!(&echoed == b"OG-ECHO!", "tunnel echo mismatch");
    // Downgrading permissions terminates already opened streams immediately.
    b.ok(LocalCommand::Permissions {
        device: a_id.clone(),
        permissions: Permissions::view_only(),
    })
    .await?;
    let mut byte = [0u8; 1];
    let end = tokio::time::timeout(Duration::from_secs(5), tunnel.read(&mut byte)).await?;
    ensure!(
        end.is_err() || end? == 0,
        "permission downgrade left tunnel open"
    );
    echo_task.abort();
    ensure!(
        !a.rpc(LocalCommand::Open {
            device: b_id.clone(),
            request: RemoteRequest::Shell(ShellRequest::default())
        })
        .await?
        .ok,
        "unauthorized shell permitted"
    );
    b.ok(LocalCommand::Permissions {
        device: a_id.clone(),
        permissions: permissions.clone(),
    })
    .await?;
    // Stop/restart the real peer process on its former port; preserve the state directory.
    let snapshot = b.ok(LocalCommand::Status).await?;
    let address = snapshot["network"]["listeners"][0]
        .as_str()
        .context("listener")?;
    let multi: libp2p::Multiaddr = address.parse()?;
    let port = multi
        .iter()
        .find_map(|p| {
            if let libp2p::multiaddr::Protocol::Udp(port) = p {
                Some(port)
            } else {
                None
            }
        })
        .context("QUIC port")?;
    b.child.kill()?;
    b.child.wait()?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    b = Daemon::start(&b.dir, Some(port)).await?;
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if a.rpc(LocalCommand::Connect {
                device: b_id.clone(),
            })
            .await
            .is_ok_and(|r| r.ok)
            {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .context("saved peer did not reconnect after daemon restart")?;
    b.ok(LocalCommand::Revoke {
        device: a_id.clone(),
    })
    .await?;
    ensure!(
        !a.rpc(LocalCommand::Connect {
            device: b_id.clone()
        })
        .await?
        .ok,
        "revoked peer authenticated"
    );
    // A fresh invitation is the only supported way to restore mutual trust.
    // Both local network runtimes still carry revocation sentinels here, so this
    // also proves re-pairing does not require either daemon to restart.
    a.ok(LocalCommand::Revoke {
        device: b_id.clone(),
    })
    .await?;
    let replacement = b
        .ok(LocalCommand::Allow {
            permissions: permissions.clone(),
            ttl: 900,
        })
        .await?;
    a.ok(LocalCommand::Pair {
        token: replacement["token"]
            .as_str()
            .context("replacement token")?
            .to_owned(),
        grant: permissions,
    })
    .await?;
    a.ok(LocalCommand::Connect { device: b_id }).await?;
    Ok(())
}

#[tokio::test]
async fn local_api_rejects_wrong_credential() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let daemon = Daemon::start(temp.path(), None).await?;
    let endpoint = daemon.endpoint()?;
    let mut stream = TcpStream::connect(endpoint.address).await?;
    write_frame(
        &mut stream,
        &LocalRequest {
            auth: "incorrect".into(),
            command: LocalCommand::Allow {
                permissions: Permissions::full_admin(),
                ttl: 900,
            },
        },
    )
    .await?;
    let mut data = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut data)).await?;
    ensure!(
        result.is_err() || result? == 0,
        "unauthorized local API request accepted"
    );
    Ok(())
}

/// Explicitly opt in: performs a real >2 GiB transfer and verification using bounded
/// buffers. A killed peer daemon interrupts the first transfer; this does not claim
/// a real router/Internet outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "large acceptance test: writes over 2 GiB; run explicitly"]
async fn multi_gigabyte_transfer_resumes_after_peer_interruption() -> Result<()> {
    use sha2::{Digest, Sha256};
    let temp = tempfile::tempdir()?;
    let a = Daemon::start(&temp.path().join("client"), None).await?;
    let mut b = Daemon::start(&temp.path().join("host"), None).await?;
    let permissions = if opengate_service::is_elevated() {
        b.ok(LocalCommand::ConfigSet {
            key: "allow_admin".into(),
            value: "true".into(),
        })
        .await?;
        Permissions::full_admin()
    } else {
        Permissions::standard()
    };
    let invitation = b
        .ok(LocalCommand::Allow {
            permissions,
            ttl: 900,
        })
        .await?;
    let paired = a
        .ok(LocalCommand::Pair {
            token: invitation["token"].as_str().context("invitation")?.into(),
            grant: Permissions::view_only(),
        })
        .await?;
    let peer = paired["device"]["peer_id"]
        .as_str()
        .context("host peer")?
        .to_owned();
    let size = 2u64 * 1024 * 1024 * 1024 + 17;
    let source = temp.path().join("large-source.bin");
    let file = std::fs::File::create(&source)?;
    file.set_len(size)?;
    drop(file);
    let source_hash = source.clone();
    let hash = tokio::task::spawn_blocking(move || -> Result<String> {
        let mut file = std::fs::File::open(source_hash)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let count = std::io::Read::read(&mut file, &mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    })
    .await??;
    eprintln!("large transfer: source checksum ready; opening initial upload");
    let mut first = a
        .open(&peer, RemoteRequest::Files)
        .await
        .context("opening initial upload")?;
    write_frame(
        &mut first,
        &FileRequest::Upload {
            path: "large.bin".into(),
            size,
            sha256: hash.clone(),
            overwrite: false,
        },
    )
    .await?;
    let ready: FileReply = read_frame(&mut first)
        .await
        .context("waiting for initial upload readiness")?;
    eprintln!("large transfer: initial stream ready");
    ensure!(
        matches!(ready, FileReply::Ready { offset: 0, .. }),
        "fresh transfer did not start at zero"
    );
    let partial = 1024u64 * 1024 * 1024;
    for offset in (0..partial).step_by(CHUNK_SIZE) {
        write_frame(
            &mut first,
            &FileReply::Chunk {
                offset,
                data: vec![0; CHUNK_SIZE],
            },
        )
        .await?;
    }
    // Wait until the host has durably persisted a nonzero prefix before interrupting it.
    let host_shared = b.dir.join("shared");
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let durable = std::fs::read_dir(&host_shared)?
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
                .filter_map(|entry| entry.metadata().ok())
                .map(|meta| meta.len())
                .max()
                .unwrap_or(0);
            if durable >= partial {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        anyhow::Ok(())
    })
    .await??;
    eprintln!("large transfer: durable prefix stored; restarting host");
    let status = b.ok(LocalCommand::Status).await?;
    let address: libp2p::Multiaddr = status["network"]["listeners"][0]
        .as_str()
        .context("listener")?
        .parse()?;
    let port = address
        .iter()
        .find_map(|p| {
            if let libp2p::multiaddr::Protocol::Udp(port) = p {
                Some(port)
            } else {
                None
            }
        })
        .context("port")?;
    b.child.kill()?;
    b.child.wait()?;
    drop(first);
    b = Daemon::start(&b.dir, Some(port))
        .await
        .context("restarting host")?;
    eprintln!("large transfer: host restarted; authenticating saved peer");
    a.ok(LocalCommand::Connect {
        device: peer.clone(),
    })
    .await?;
    eprintln!("large transfer: saved peer authenticated; resuming upload");
    let mut resumed = None;
    let mut final_count = 0;
    opengate_files::push_with_progress(
        a.open(&peer, RemoteRequest::Files).await?,
        &source,
        "large.bin",
        false,
        tokio_util::sync::CancellationToken::new(),
        |progress| {
            resumed.get_or_insert(progress.transferred);
            final_count = progress.transferred;
        },
    )
    .await
    .context("resuming large upload")?;
    ensure!(
        resumed == Some(partial),
        "large transfer did not resume the durable prefix: {resumed:?}"
    );
    ensure!(
        final_count == size,
        "large transfer did not report full length"
    );
    let uploaded = b.dir.join("shared/large.bin");
    let actual = tokio::task::spawn_blocking(move || -> Result<(u64, String)> {
        let mut file = std::fs::File::open(uploaded)?;
        let len = file.metadata()?.len();
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let count = std::io::Read::read(&mut file, &mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok((len, format!("{:x}", hasher.finalize())))
    })
    .await??;
    ensure!(
        actual == (size, hash),
        "large uploaded file length or checksum differs"
    );
    eprintln!("verified {size} bytes; resumed at {partial} bytes after peer process interruption");
    Ok(())
}

/// Invitations can carry several direct/relay address hints and exceed 512 bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_pairs_with_long_token_on_standard_input() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let a = Daemon::start(&temp.path().join("stdin-client"), None).await?;
    let b = Daemon::start(&temp.path().join("stdin-host"), None).await?;
    let invitation = b
        .ok(LocalCommand::Allow {
            permissions: Permissions::view_only(),
            ttl: 900,
        })
        .await?;
    let mut token = opengate_security::PairingToken::decode(
        invitation["token"].as_str().context("invitation")?,
    )?;
    token.addresses = vec![token.addresses[0].clone(); 5];
    let encoded = token.encode()?;
    ensure!(
        encoded.len() > 512,
        "test needs an invitation longer than 512 bytes"
    );
    let data_dir = a.dir.clone();
    let output = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut process = Command::new(env!("CARGO_BIN_EXE_opengate"))
            .arg("--data-dir")
            .arg(data_dir)
            .args(["connect", "--token-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        std::io::Write::write_all(
            &mut process.stdin.take().context("stdin")?,
            encoded.as_bytes(),
        )?;
        Ok(process.wait_with_output()?)
    })
    .await??;
    ensure!(
        output.status.success(),
        "CLI pairing failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        a.ok(LocalCommand::Devices)
            .await?
            .as_array()
            .context("saved devices")?
            .len()
            == 1,
        "CLI did not persist the paired device"
    );
    Ok(())
}
