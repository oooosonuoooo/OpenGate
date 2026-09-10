//! Explicit text-only clipboard access through the logged-in desktop's public tools.
use anyhow::{Context, Result, bail, ensure};
use opengate_protocol::{RemoteRequest, Reply};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
const LIMIT: usize = 64 * 1024;

#[cfg(not(windows))]
fn executable(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|path| path.is_file())
    })
}
fn backend(write: bool) -> Result<Command> {
    #[cfg(windows)]
    {
        ensure!(
            matches!(std::env::var("SESSIONNAME"), Ok(name) if name != "Services"),
            "clipboard requires the owner's interactive desktop session; a Windows service cannot access it"
        );
        let mut command = Command::new("powershell.exe");
        let script = if write {
            "$ErrorActionPreference='Stop'; Set-Clipboard -Value ([Console]::In.ReadToEnd())"
        } else {
            "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); [Console]::Write((Get-Clipboard -Raw))"
        };
        command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
        Ok(command)
    }
    #[cfg(not(windows))]
    {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            let name = if write { "wl-copy" } else { "wl-paste" };
            let path=executable(name).with_context(||format!("install wl-clipboard to enable clipboard access in this Wayland session ({name} missing)"))?;
            let mut command = Command::new(path);
            if write {
                command.args(["--type", "text/plain;charset=utf-8"]);
            } else {
                command.args(["--no-newline", "--type", "text"]);
            }
            return Ok(command);
        }
        ensure!(
            std::env::var_os("DISPLAY").is_some(),
            "clipboard requires the owner's interactive desktop session; a headless service cannot access it"
        );
        let path = executable("xclip")
            .context("install xclip to enable clipboard access in this X11 session")?;
        let mut command = Command::new(path);
        command.args(["-selection", "clipboard"]);
        command.arg(if write { "-in" } else { "-out" });
        Ok(command)
    }
}
async fn invoke(text: Option<&str>) -> Result<String> {
    if let Some(text) = text {
        ensure!(text.len() <= LIMIT, "clipboard text exceeds 64 KiB");
    }
    let mut command = backend(text.is_some())?;
    command
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(if text.is_some() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .context("starting the desktop clipboard provider")?;
    let mut stdin = child.stdin.take().context("clipboard stdin unavailable")?;
    let output = child.stdout.take();
    let operation = async {
        if let Some(text) = text {
            stdin.write_all(text.as_bytes()).await?;
        }
        drop(stdin);
        let mut bytes = Vec::new();
        if let Some(output) = output {
            output
                .take((LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .await?;
        }
        ensure!(bytes.len() <= LIMIT, "clipboard text exceeds 64 KiB");
        let status = child.wait().await?;
        ensure!(
            status.success(),
            "desktop clipboard provider rejected the request"
        );
        String::from_utf8(bytes).context("clipboard content is not UTF-8 text")
    };
    tokio::time::timeout(Duration::from_secs(5), operation)
        .await
        .context("desktop clipboard provider timed out")?
}
pub async fn get() -> Result<String> {
    invoke(None).await
}
pub async fn set(text: &str) -> Result<()> {
    invoke(Some(text)).await?;
    Ok(())
}
async fn remote(dir: &std::path::Path, device: &str, request: RemoteRequest) -> Result<Reply> {
    let reply = crate::client::rpc(
        dir,
        opengate_protocol::LocalCommand::Open {
            device: device.into(),
            request,
        },
    )
    .await?;
    reply.check()?;
    Ok(reply)
}
pub async fn run(dir: PathBuf, device: String, mode: &str) -> Result<()> {
    match mode {
        "get" => {
            let reply = remote(&dir, &device, RemoteRequest::ClipboardGet).await?;
            set(reply.data["text"]
                .as_str()
                .context("missing clipboard text")?)
            .await?;
        }
        "send" => {
            remote(
                &dir,
                &device,
                RemoteRequest::ClipboardSet { text: get().await? },
            )
            .await?;
        }
        "sync" => {
            // Starting synchronization copies remote text locally only because the owner
            // explicitly invoked sync. Clipboard content is never printed or logged.
            let reply = remote(&dir, &device, RemoteRequest::ClipboardGet).await?;
            let mut last = reply.data["text"]
                .as_str()
                .context("missing clipboard text")?
                .to_owned();
            set(&last).await?;
            eprintln!("Text clipboard synchronization enabled for {device}; Ctrl+C stops it.");
            loop {
                tokio::select! {_=tokio::signal::ctrl_c()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
                let local = get().await?;
                if local != last {
                    remote(
                        &dir,
                        &device,
                        RemoteRequest::ClipboardSet {
                            text: local.clone(),
                        },
                    )
                    .await?;
                    last = local;
                } else {
                    let reply = remote(&dir, &device, RemoteRequest::ClipboardGet).await?;
                    let text = reply.data["text"]
                        .as_str()
                        .context("missing clipboard text")?;
                    if text != last {
                        set(text).await?;
                        last = text.into();
                    }
                }
            }
        }
        _ => bail!("clipboard mode must be get, send or sync"),
    }
    Ok(())
}
