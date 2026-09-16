//! Interactive PTY service over an already authenticated OpenGate stream.

use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow, bail};
use crossterm::{
    event::{Event, EventStream},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use futures::StreamExt;
use opengate_protocol::{ShellRequest, TerminalFrame, read_frame, write_frame};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const QUEUE: usize = 32;
const MAX_DIMENSION: u16 = 1_000;

/// Serve an interactive shell. The OpenRequest and its authorization reply are
/// deliberately handled by the daemon before this function is called.
pub async fn serve<S>(stream: S, request: ShellRequest, cancel: CancellationToken) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let size = pty_size(request.rows, request.cols);
    let pty = NativePtySystem::default()
        .openpty(size)
        .context("creating terminal PTY")?;
    let command = command(&request)?;
    let mut child = pty.slave.spawn_command(command).context("starting shell")?;
    drop(pty.slave);
    let killer = Arc::new(Mutex::new(child.clone_killer()));
    let _kill_on_drop = KillOnDrop(killer.clone());
    let reader = pty
        .master
        .try_clone_reader()
        .context("opening PTY output")?;
    let writer = pty.master.take_writer().context("opening PTY input")?;
    let (mut input_r, mut output_w) = tokio::io::split(stream);
    // read_exact-based framing must not be cancelled by unrelated output events.
    // One reader task owns frame assembly for the lifetime of this stream half.
    let (incoming_tx, mut incoming_rx) = mpsc::channel(QUEUE);
    let reader_task = tokio::spawn(async move {
        while let Ok(frame) = read_frame::<TerminalFrame, _>(&mut input_r).await {
            if incoming_tx.send(frame).await.is_err() {
                break;
            }
        }
    });
    let _reader_guard = AbortOnDrop(reader_task);
    let (control_tx, mut control_rx) = mpsc::channel::<TerminalFrame>(QUEUE);
    let mut control_tx = Some(control_tx);
    let (out_tx, mut out_rx) = mpsc::channel::<TerminalFrame>(QUEUE);
    let local_cancel = cancel.child_token();
    let cancel_control = local_cancel.clone();
    let killer_control = killer.clone();
    let mut control = Some(tokio::task::spawn_blocking(move || -> Result<()> {
        let mut writer = writer;
        while let Some(frame) = control_rx.blocking_recv() {
            match frame {
                TerminalFrame::Input(bytes) => {
                    writer.write_all(&bytes)?;
                    writer.flush()?;
                }
                TerminalFrame::Resize { rows, cols } => pty.master.resize(pty_size(rows, cols))?,
                TerminalFrame::Close => break,
                _ => bail!("client sent invalid terminal frame"),
            }
            if cancel_control.is_cancelled() {
                break;
            }
        }
        let _ = killer_control
            .lock()
            .map_err(|_| anyhow!("terminal killer poisoned"))?
            .kill();
        Ok(())
    }));
    let output = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut reader = reader;
        let mut buffer = [0u8; 8192];
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            if out_tx
                .blocking_send(TerminalFrame::Output(buffer[..n].to_vec()))
                .is_err()
            {
                break;
            }
        }
        Ok(())
    });
    // Child waiting is separate from control so cancellation can kill through clone_killer.
    let (exit_sender, mut exit_receiver) = mpsc::channel(1);
    tokio::task::spawn_blocking(move || {
        let status = child.wait();
        let _ = exit_sender.blocking_send(status.map(|s| s.exit_code()));
    });
    let mut output_done = false;
    let mut exit_code = None;
    loop {
        if output_done && let Some(code) = exit_code {
            write_frame(&mut output_w, &TerminalFrame::Exit { code }).await?;
            break;
        }
        tokio::select! {
            _=cancel.cancelled()=>{break},
            frame=incoming_rx.recv() => match frame {
                Some(frame @ (TerminalFrame::Input(_) | TerminalFrame::Resize { .. } | TerminalFrame::Close)) => {
                    if let Some(sender) = control_tx.as_ref()
                        && sender.send(frame).await.is_err()
                    {
                        break
                    }
                },
                _ => break,
            },
            outbound=out_rx.recv(), if !output_done => match outbound { Some(frame)=>write_frame(&mut output_w,&frame).await?, None=>output_done=true },
            status=exit_receiver.recv(), if exit_code.is_none()=> {
                exit_code=Some(status.ok_or_else(||anyhow!("terminal exit waiter stopped"))??);
                // ConPTY may keep its output pipe open until the pseudo-console
                // control handle is released. Close the control sender as soon
                // as the child exits so output can reach EOF and the Exit frame
                // can be delivered on Windows as well as Unix.
                control_tx = None;
                if let Some(task) = control.take() {
                    // Awaiting the control task here is important on ConPTY:
                    // dropping its master handle is what lets the output
                    // reader observe EOF. Waiting until after the output
                    // reader finishes would deadlock the two tasks.
                    let _ = task.await;
                }
            },
        }
    }
    drop(control_tx);
    local_cancel.cancel();
    if let Some(task) = control {
        let _ = task.await;
    }
    let _ = output.await;
    Ok(())
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn command(request: &ShellRequest) -> Result<CommandBuilder> {
    let shell = request.shell.clone().unwrap_or_else(default_shell);
    if shell.trim().is_empty() || shell.contains('\0') {
        bail!("invalid shell path")
    }
    let mut cmd = CommandBuilder::new(shell);
    #[cfg(windows)]
    if request.shell.is_none() {
        cmd.args(["-NoLogo"]);
    }
    #[cfg(not(windows))]
    if request.shell.is_none() {
        cmd.arg("-i");
    }
    if let Some(cwd) = &request.cwd {
        if cwd.contains('\0') {
            bail!("invalid working directory")
        }
        cmd.cwd(cwd);
    }
    for (key, value) in &request.env {
        if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
            bail!("invalid terminal environment")
        };
        cmd.env(key, value);
    }
    Ok(cmd)
}
fn default_shell() -> String {
    #[cfg(windows)]
    {
        "powershell.exe".into()
    }
    #[cfg(not(windows))]
    {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into())
    }
}

/// Attach the local terminal after the caller has opened and acknowledged the
/// remote shell request. Raw mode is always restored on every return path.
pub async fn client<S>(stream: S, _request: ShellRequest) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let raw = RawMode::enter()?;
    let (mut read, mut write) = tokio::io::split(stream);
    let (remote_tx, mut remote_rx) = mpsc::channel(QUEUE);
    let remote_task = tokio::spawn(async move {
        loop {
            let frame = read_frame::<TerminalFrame, _>(&mut read).await;
            let failed = frame.is_err();
            if remote_tx.send(frame).await.is_err() || failed {
                break;
            }
        }
    });
    let _remote_guard = AbortOnDrop(remote_task);
    let (input_tx, mut input_rx) = mpsc::channel::<TerminalFrame>(QUEUE);
    let input = tokio::spawn(async move {
        let mut events = EventStream::new();
        while let Some(event) = events.next().await {
            match event? {
                Event::Key(key) => {
                    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    let bytes = match key.code {
                        KeyCode::Char(c)
                            if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' =>
                        {
                            vec![3]
                        }
                        KeyCode::Char(c)
                            if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'd' =>
                        {
                            vec![4]
                        }
                        KeyCode::Char(c) => c.to_string().into_bytes(),
                        KeyCode::Enter => vec![b'\r'],
                        KeyCode::Backspace => vec![127],
                        KeyCode::Tab => vec![b'\t'],
                        KeyCode::Esc => vec![27],
                        KeyCode::Up => b"\x1b[A".to_vec(),
                        KeyCode::Down => b"\x1b[B".to_vec(),
                        KeyCode::Left => b"\x1b[D".to_vec(),
                        KeyCode::Right => b"\x1b[C".to_vec(),
                        _ => Vec::new(),
                    };
                    if !bytes.is_empty()
                        && input_tx.send(TerminalFrame::Input(bytes)).await.is_err()
                    {
                        break;
                    }
                }
                Event::Resize(cols, rows)
                    if input_tx
                        .send(TerminalFrame::Resize { rows, cols })
                        .await
                        .is_err() =>
                {
                    break;
                }
                _ => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    write_frame(&mut write, &TerminalFrame::Resize { rows, cols }).await?;
    let result=async {loop{tokio::select!{frame=input_rx.recv()=>match frame{Some(f)=>write_frame(&mut write,&f).await?,None=>break},frame=remote_rx.recv()=>match frame.ok_or_else(||anyhow!("terminal stream closed"))??{TerminalFrame::Output(bytes)=>tokio::io::AsyncWriteExt::write_all(&mut tokio::io::stdout(),&bytes).await?,TerminalFrame::Exit{..}|TerminalFrame::Close=>break,_=>{}}}}Ok::<(),anyhow::Error>(())}.await;
    input.abort();
    drop(raw);
    result
}
struct RawMode;
impl RawMode {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enabling raw terminal mode")?;
        Ok(Self)
    }
}
impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}
struct KillOnDrop(Arc<Mutex<Box<dyn portable_pty::ChildKiller + Send + Sync>>>);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Ok(mut killer) = self.0.lock() {
            let _ = killer.kill();
        }
    }
}
fn pty_size(rows: u16, cols: u16) -> PtySize {
    PtySize {
        rows: rows.clamp(1, MAX_DIMENSION),
        cols: cols.clamp(1, MAX_DIMENSION),
        pixel_width: 0,
        pixel_height: 0,
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn pty_carries_marker_and_resize() -> Result<()> {
        let (server, mut client) = tokio::io::duplex(256 * 1024);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve(
            server,
            ShellRequest {
                shell: Some("/bin/sh".into()),
                ..Default::default()
            },
            cancel,
        ));
        write_frame(
            &mut client,
            &TerminalFrame::Resize {
                rows: 41,
                cols: 121,
            },
        )
        .await?;
        write_frame(
            &mut client,
            &TerminalFrame::Input(
                b"printf OPENGATE_PTY_MARKER; dd if=/dev/zero bs=1024 count=128 2>/dev/null | tr '\\000' x; printf OPENGATE_PTY_TRAILER; exit\r".to_vec(),
            ),
        )
        .await?;
        let mut output = Vec::new();
        loop {
            match timeout(
                Duration::from_secs(5),
                read_frame::<TerminalFrame, _>(&mut client),
            )
            .await??
            {
                TerminalFrame::Output(bytes) => output.extend(bytes),
                TerminalFrame::Exit { .. } => break,
                _ => {}
            }
        }
        let output = String::from_utf8_lossy(&output);
        assert!(output.contains("OPENGATE_PTY_MARKER"));
        assert!(output.contains("OPENGATE_PTY_TRAILER"));
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_terminates_a_running_pty_shell() -> Result<()> {
        let (server, mut client) = tokio::io::duplex(64 * 1024);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve(
            server,
            ShellRequest {
                shell: Some("/bin/sh".into()),
                ..Default::default()
            },
            cancel.clone(),
        ));
        write_frame(&mut client, &TerminalFrame::Input(b"sleep 30\r".to_vec())).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        timeout(Duration::from_secs(3), task).await???;
        Ok(())
    }
}
