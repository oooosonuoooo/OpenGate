mod client;
mod daemon;
mod tui;

use std::{path::PathBuf,collections::BTreeMap};
use anyhow::{Context,Result,bail,ensure};
use clap::{Parser,Subcommand};
use opengate_protocol::*;

#[derive(Parser)]
#[command(name="opengate",version,about="Pair once, securely access your authorized Windows and Linux devices")]
struct Cli {
    #[arg(long,global=true,env="OPENGATE_DATA_DIR")]
    data_dir:Option<PathBuf>,
    #[command(subcommand)]
    command:Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show device identity, active network paths and measured connection details.
    Status {#[arg(long)] network:bool},
    /// Allow one new trusted device using an expiring token.
    Allow {#[arg(long,default_value="standard")] permissions:String,#[arg(long,default_value_t=900)] ttl:u64,#[arg(long)] acknowledge_full_admin:bool},
    /// Pair with a token or authenticate a saved device.
    Connect {token_or_device:String,#[arg(long,default_value="view-only")] grant:String,#[arg(long)] acknowledge_full_admin:bool},
    Devices,
    Device {#[command(subcommand)] command:DeviceCommand},
    /// Interactive native PTY/ConPTY shell; does not require SSH.
    Shell {device:String,#[arg(long)] shell:Option<String>,#[arg(long)] cwd:Option<String>,#[arg(long="env",value_parser=parse_env)] env:Vec<(String,String)>,#[arg(long)] command:Option<String>},
    /// Upload a file or directory inside the host's configured file root.
    Push {device:String,source:String,destination:String,#[arg(long)] overwrite:bool,#[arg(long)] no_resume:bool},
    Pull {device:String,source:String,destination:String,#[arg(long)] overwrite:bool,#[arg(long)] no_resume:bool},
    Files {device:String,#[command(subcommand)] command:FileCommand},
    /// Forward TCP to an authorized host service (SSH, HTTP, database, RDP).
    Forward {device:String,#[arg(long)] local:String,#[arg(long)] remote:String,#[arg(long)] acknowledge_public_bind:bool},
    Socks {device:String,#[arg(long,default_value="127.0.0.1:1080")] listen:String,#[arg(long)] acknowledge_public_bind:bool},
    /// Tunnel an already enabled RDP or VNC server.
    Desktop {device:String,#[arg(long,default_value="13389")] local:String,#[arg(long,default_value="127.0.0.1:3389")] remote:String},
    Diagnose {device:Option<String>},
    Scan {#[arg(long,default_value_t=3)] seconds:u64},
    Daemon {#[arg(long)] listen:Vec<String>},
    Relay {#[arg(long)] listen:Vec<String>},
    Service {#[command(subcommand)] command:ServiceCommand},
    Pairing {#[command(subcommand)] command:PairingCommand},
    Logs {#[arg(long,default_value_t=50)] limit:usize},
    Config {#[command(subcommand)] command:Option<ConfigCommand>},
    Update,
    Version,
}
#[derive(Subcommand)] enum DeviceCommand {
    Rename {device:String,name:String}, Info {device:String}, Revoke {device:String},
    Permissions {device:String,#[arg(long)] preset:Option<String>,#[arg(long)] clipboard:Option<bool>,#[arg(long)] acknowledge_full_admin:bool},
}
#[derive(Subcommand)] enum FileCommand {
    List {#[arg(default_value=".")] path:String}, Stat {path:String}, Mkdir{path:String}, Rename{from:String,to:String},Copy{from:String,to:String},Delete{path:String,#[arg(long)] recursive:bool,#[arg(long)] yes:bool},Chmod{path:String,mode:u32},
}
#[derive(Subcommand)] enum ServiceCommand {Start,Stop,Status,PrintUnit,Install {#[arg(long)] system:bool,#[arg(long)] full_admin:bool},Uninstall {#[arg(long)] system:bool}}
#[derive(Subcommand)] enum PairingCommand {Cancel}
#[derive(Subcommand)] enum ConfigCommand {Get,Set{key:String,value:String}}

fn parse_env(value:&str)->Result<(String,String),String> {value.split_once('=').map(|(k,v)|(k.into(),v.into())).ok_or("use NAME=VALUE".into())}
fn grants(preset:&str,ack:bool)->Result<Permissions> {let p=Permissions::preset(preset)?;ensure!(!p.full_admin || ack,"Full Admin Access requires --acknowledge-full-admin and an owner-configured privileged service");if p.full_admin {eprintln!("FULL ADMIN ACCESS ENABLED for this grant");}Ok(p)}
fn print(value:impl serde::Serialize)->Result<()> {println!("{}",serde_json::to_string_pretty(&value)?);Ok(())}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_|"warn".into())).with_writer(std::io::stderr).init();
    if let Err(error)=entry().await {eprintln!("OpenGate: {error:#}");std::process::exit(1);}
}
async fn entry()->Result<()> {
    let cli=Cli::parse();
    let dir=cli.data_dir.unwrap_or_else(||directories::ProjectDirs::from("org","OpenGate","OpenGate").map(|p|p.data_local_dir().to_path_buf()).unwrap_or_else(||PathBuf::from(".opengate")));
    if let Some(command)=cli.command {execute(dir,command).await} else {tui::run(dir).await}
}

async fn execute(dir:PathBuf,command:Command)->Result<()> {
    match command {
        Command::Daemon{listen}=>daemon::run(dir,false,listen).await,
        Command::Relay{listen}=>daemon::run(dir,true,listen).await,
        Command::Version=>{println!("OpenGate {} · protocol {}",env!("CARGO_PKG_VERSION"),VERSION);Ok(())},
        Command::Status{..}=>print(client::rpc(&dir,LocalCommand::Status).await?.data),
        Command::Allow{permissions,ttl,acknowledge_full_admin}=>{
            let reply=client::rpc(&dir,LocalCommand::Allow{permissions:grants(&permissions,acknowledge_full_admin)?,ttl}).await?;
            println!("OpenGate — Allow Access\nDevice: {}\nDevice ID: {}\nExpires (Unix time): {}\nPairing Token:\n{}\nWaiting for an authorized device. Regenerate with `opengate allow`; cancel with `opengate pairing cancel`.",reply.data["device"]["name"].as_str().unwrap_or(""),reply.data["device"]["peer_id"].as_str().unwrap_or(""),reply.data["expires_at"],reply.data["token"].as_str().context("missing token")?);Ok(())
        },
        Command::Connect{token_or_device,grant,acknowledge_full_admin}=>{
            let command=if token_or_device.starts_with("OG1") {LocalCommand::Pair{token:token_or_device,grant:grants(&grant,acknowledge_full_admin)?}} else {LocalCommand::Connect{device:token_or_device}};
            print(client::rpc(&dir,command).await?.data)
        },
        Command::Devices=>print(client::rpc(&dir,LocalCommand::Devices).await?.data),
        Command::Device{command}=>match command {
            DeviceCommand::Rename{device,name}=>print(client::rpc(&dir,LocalCommand::Rename{device,name}).await?.data),
            DeviceCommand::Revoke{device}=>print(client::rpc(&dir,LocalCommand::Revoke{device}).await?.data),
            DeviceCommand::Info{device}=>{let store=opengate_core::Store::open(&dir)?;print(store.device(&device)?)},
            DeviceCommand::Permissions{device,preset,clipboard,acknowledge_full_admin}=>{
                client::ensure_daemon(&dir).await?;
                let saved=opengate_core::Store::open(&dir)?.device(&device)?;
                if preset.is_none() && clipboard.is_none(){return print(saved.permissions);}
                let mut permissions=match preset {Some(p)=>grants(&p,acknowledge_full_admin)?,None=>saved.permissions};
                if let Some(enabled)=clipboard {permissions.clipboard=enabled;}
                print(client::rpc(&dir,LocalCommand::Permissions{device,permissions}).await?.data)
            },
        },
        Command::Shell{device,shell,cwd,env,command}=>client::shell(&dir,&device,ShellRequest{shell,cwd,env:env.into_iter().collect::<BTreeMap<_,_>>(),..ShellRequest::default()},command).await,
        Command::Push{device,source,destination,overwrite,no_resume}=>client::transfer(&dir,&device,&source,&destination,true,overwrite,!no_resume).await,
        Command::Pull{device,source,destination,overwrite,no_resume}=>client::transfer(&dir,&device,&source,&destination,false,overwrite,!no_resume).await,
        Command::Files{device,command}=>{
            let request=match command {FileCommand::List{path}=>FileRequest::List{path},FileCommand::Stat{path}=>FileRequest::Stat{path},FileCommand::Mkdir{path}=>FileRequest::Mkdir{path},FileCommand::Rename{from,to}=>FileRequest::Rename{from,to},FileCommand::Copy{from,to}=>FileRequest::Copy{from,to},FileCommand::Delete{path,recursive,yes}=>{ensure!(yes,"deletion requires --yes");FileRequest::Delete{path,recursive}},FileCommand::Chmod{path,mode}=>FileRequest::SetPermissions{path,mode}};
            print(client::file_request(&dir,&device,request).await?)
        },
        Command::Forward{device,local,remote,acknowledge_public_bind}=>client::forward(dir,device,local,remote,false,acknowledge_public_bind,false).await,
        Command::Socks{device,listen,acknowledge_public_bind}=>client::forward(dir,device,listen,String::new(),false,acknowledge_public_bind,true).await,
        Command::Desktop{device,local,remote}=>{eprintln!("Connect your installed RDP/VNC client to 127.0.0.1:{local}. The remote desktop service must already be enabled by its owner.");client::forward(dir,device,local,remote,true,false,false).await},
        Command::Diagnose{device}=>{
            if let Some(device)=device {let start=std::time::Instant::now();let result=client::rpc(&dir,LocalCommand::Connect{device}).await;print(serde_json::json!({"authenticated":result.is_ok(),"control_roundtrip_ms":start.elapsed().as_millis(),"error":result.err().map(|e|e.to_string())}))?;}
            print(client::rpc(&dir,LocalCommand::Status).await?.data)
        },
        Command::Scan{seconds}=>{client::ensure_daemon(&dir).await?;tokio::time::sleep(std::time::Duration::from_secs(seconds.min(30))).await;let reply=client::rpc(&dir,LocalCommand::Status).await?;print(&reply.data["network"]["discovered"])},
        Command::Pairing{command:PairingCommand::Cancel}=>print(client::rpc(&dir,LocalCommand::CancelPairing).await?.data),
        Command::Logs{limit}=>print(client::rpc(&dir,LocalCommand::Logs{limit}).await?.data),
        Command::Config{command}=>match command {None|Some(ConfigCommand::Get)=>print(client::rpc(&dir,LocalCommand::ConfigGet).await?.data),Some(ConfigCommand::Set{key,value})=>print(client::rpc(&dir,LocalCommand::ConfigSet{key,value}).await?.data)},
        Command::Service{command}=>match command {
            ServiceCommand::Start=>{let endpoint=client::ensure_daemon(&dir).await?;println!("OpenGate daemon running (PID {})",endpoint.pid);Ok(())},
            ServiceCommand::Stop=>print(client::rpc(&dir,LocalCommand::Shutdown).await?.data),
            ServiceCommand::Status=>{let endpoint=daemon::endpoint(&dir)?;println!("OpenGate daemon PID {} at {}",endpoint.pid,endpoint.address);Ok(())},
            ServiceCommand::PrintUnit=>{println!("{}",opengate_service::linux_unit(&std::env::current_exe()?,&dir,false));Ok(())},
            ServiceCommand::Install{system,full_admin}=>opengate_service::install(&std::env::current_exe()?,&dir,system,full_admin),
            ServiceCommand::Uninstall{system}=>opengate_service::uninstall(system),
        },
        Command::Update=>bail!("automatic updates are disabled: this build has no configured release signing key. Install a locally verified release package; no unsigned binary will be downloaded or executed"),
    }
}
