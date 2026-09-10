//! Small keyboard-first TUI; actions use the same authenticated local daemon API as the CLI.
use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use opengate_protocol::LocalCommand;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    time::Duration,
};

async fn pairing_view(dir: &Path) -> Result<()> {
    let mut reply = crate::client::rpc(
        dir,
        LocalCommand::Allow {
            permissions: opengate_protocol::Permissions::standard(),
            ttl: 900,
        },
    )
    .await?;
    loop {
        let expires_at = reply.data["expires_at"]
            .as_u64()
            .context("missing pairing expiry")?;
        let remaining = expires_at.saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        let status = crate::client::rpc(dir, LocalCommand::Status).await?;
        let connections = status.data["network"]["connections"]
            .as_array()
            .map_or(0, Vec::len);
        let device = &reply.data["device"];
        println!(
            "\nAllow Access\nDevice: {}\nDevice ID: {}\nPairing Token: {}\nExpires in: {}:{:02}\nStatus: {} connection(s) active; waiting for an authorized device.\n\nC Copy token to this desktop clipboard · R Regenerate · X Cancel · Enter Back",
            device["name"].as_str().unwrap_or("Device"),
            device["peer_id"].as_str().unwrap_or("—"),
            reply.data["token"]
                .as_str()
                .context("missing pairing token")?,
            remaining / 60,
            remaining % 60,
            connections,
        );
        match prompt("Action")?.to_ascii_lowercase().as_str() {
            "c" if remaining == 0 => println!("This token has expired. Choose R to regenerate it."),
            "c" => {
                crate::clipboard::set(
                    reply.data["token"]
                        .as_str()
                        .context("missing pairing token")?,
                )
                .await?;
                println!("Pairing token copied to the interactive desktop clipboard.");
            }
            "r" => {
                reply = crate::client::rpc(
                    dir,
                    LocalCommand::Allow {
                        permissions: opengate_protocol::Permissions::standard(),
                        ttl: 900,
                    },
                )
                .await?;
            }
            "x" => {
                crate::client::rpc(dir, LocalCommand::CancelPairing).await?;
                println!("Pairing token cancelled.");
                return Ok(());
            }
            "" => return Ok(()),
            _ => println!("Choose C, R, X, or Enter."),
        }
    }
}

struct Screen;
impl Drop for Screen {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_owned())
}

pub async fn run(dir: PathBuf) -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        println!(
            "OpenGate — Connect to Device · Allow Access · Saved Devices · Connections · Settings · Diagnostics\nRun `opengate --help` for commands. The interactive menu requires a terminal."
        );
        return Ok(());
    }
    crate::client::ensure_daemon(&dir).await?;
    let mut selected = 0;
    loop {
        let status = crate::client::rpc(&dir, LocalCommand::Status).await?;
        let title = format!(
            " OpenGate · {} ",
            status.data["device"]["name"].as_str().unwrap_or("Device")
        );
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        let screen = Screen;
        let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        let options = [
            "Connect to Device",
            "Allow Access",
            "Saved Devices",
            "Connections",
            "Settings",
            "Diagnostics",
            "Exit",
        ];
        let mut list_state = ListState::default().with_selected(Some(selected));
        let chosen = loop {
            terminal.draw(|frame|{
                let layout=Layout::vertical([Constraint::Length(3),Constraint::Min(10),Constraint::Length(4)]).split(frame.area());
                frame.render_widget(Paragraph::new("Pair once. Access your authorized computers whenever a viable network path is available.").block(Block::default().title(title.as_str()).borders(Borders::ALL)),layout[0]);
                let items=options.iter().enumerate().map(|(i,text)|ListItem::new(Line::from(format!("  {}. {}",i+1,text))));
                frame.render_stateful_widget(List::new(items).highlight_style(Style::default().bg(Color::Blue).fg(Color::White)).highlight_symbol("› ").block(Block::default().borders(Borders::ALL)),layout[1],&mut list_state);
                let connections=status.data["network"]["connections"].as_array().map_or(0,Vec::len);
                frame.render_widget(Paragraph::new(format!("↑/↓ or 1–7 select · Enter open · Q exit\n{connections} transport connection(s) · Permissions checked separately for every remote operation")).block(Block::default().borders(Borders::ALL)),layout[2]);
            })?;
            if event::poll(Duration::from_millis(250))?
                && let Event::Key(key) = event::read()?
            {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Up => selected = (selected + options.len() - 1) % options.len(),
                    KeyCode::Down => selected = (selected + 1) % options.len(),
                    KeyCode::Char('q') | KeyCode::Esc => break 6,
                    KeyCode::Char(c) if ('1'..='7').contains(&c) => {
                        selected = c as usize - '1' as usize;
                        break selected;
                    }
                    KeyCode::Enter => break selected,
                    _ => {}
                }
                list_state.select(Some(selected));
            }
        };
        drop(terminal);
        drop(screen);
        if chosen == 6 {
            return Ok(());
        }
        let result: Result<()> = async {
            match chosen {
                0 => {
                    let token_or_device = prompt("Pairing token or saved device")?;
                    crate::execute(
                        dir.clone(),
                        crate::Command::Connect {
                            token_or_device: Some(token_or_device),
                            token_stdin: false,
                            grant: "view-only".into(),
                            acknowledge_full_admin: false,
                        },
                    )
                    .await?;
                }
                1 => {
                    pairing_view(&dir).await?;
                }
                2 => {
                    crate::execute(dir.clone(), crate::Command::Devices).await?;
                    let action = prompt("S shell · D details · R rename · X revoke · Enter back")?;
                    if !action.is_empty() {
                        let device = prompt("Device name, ID or number")?;
                        match action.to_ascii_lowercase().as_str() {
                            "s" => {
                                crate::execute(
                                    dir.clone(),
                                    crate::Command::Shell {
                                        device,
                                        shell: None,
                                        cwd: None,
                                        env: vec![],
                                        command: None,
                                    },
                                )
                                .await?
                            }
                            "d" => {
                                crate::execute(
                                    dir.clone(),
                                    crate::Command::Device {
                                        command: crate::DeviceCommand::Info { device },
                                    },
                                )
                                .await?
                            }
                            "r" => {
                                let name = prompt("New nickname")?;
                                crate::execute(
                                    dir.clone(),
                                    crate::Command::Device {
                                        command: crate::DeviceCommand::Rename { device, name },
                                    },
                                )
                                .await?;
                            }
                            "x" if prompt(
                                "Type REVOKE to remove trust and close active sessions",
                            )? == "REVOKE" =>
                            {
                                crate::execute(
                                    dir.clone(),
                                    crate::Command::Device {
                                        command: crate::DeviceCommand::Revoke { device },
                                    },
                                )
                                .await?;
                            }
                            _ => {}
                        }
                    }
                }
                3 => crate::execute(dir.clone(), crate::Command::Status { network: true }).await?,
                4 => {
                    crate::execute(dir.clone(), crate::Command::Config { command: None }).await?;
                    let key = prompt("Setting to change, or Enter back")?;
                    if !key.is_empty() {
                        let value = prompt("New value")?;
                        crate::execute(
                            dir.clone(),
                            crate::Command::Config {
                                command: Some(crate::ConfigCommand::Set { key, value }),
                            },
                        )
                        .await?;
                    }
                }
                5 => {
                    let device = prompt("Device to authenticate, or Enter for local diagnostics")?;
                    crate::execute(
                        dir.clone(),
                        crate::Command::Diagnose {
                            device: (!device.is_empty()).then_some(device),
                        },
                    )
                    .await?;
                }
                _ => {}
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            eprintln!("OpenGate: {error:#}");
        }
        let _ = prompt("Press Enter to return");
    }
}
