//! Acceptance checks use real daemon processes, persistent state and libp2p streams.
use std::{path::{Path,PathBuf},process::{Child,Command,Stdio},time::Duration};
use anyhow::{Context,Result,ensure};
use opengate_protocol::*;
use serde::Deserialize;
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::TcpStream};

#[derive(Deserialize)] struct Endpoint {address:String,secret:String}
struct Daemon {child:Child,dir:PathBuf}
impl Drop for Daemon {fn drop(&mut self){let _=self.child.kill();let _=self.child.wait();}}
impl Daemon {
    async fn start(dir:&Path,port:Option<u16>)->Result<Self>{
        let listen=format!("/ip4/127.0.0.1/udp/{}/quic-v1",port.unwrap_or(0));
        let child=Command::new(env!("CARGO_BIN_EXE_opengate")).arg("--data-dir").arg(dir).arg("daemon").arg("--listen").arg(listen).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
        let mut daemon=Self{child,dir:dir.to_owned()};
        for _ in 0..150 {
            if let Some(status)=daemon.child.try_wait()?{anyhow::bail!("test daemon exited: {status}");}
            if let Ok(reply)=daemon.rpc(LocalCommand::Status).await {
                if reply.ok && reply.data["network"]["listeners"].as_array().is_some_and(|a|!a.is_empty()){return Ok(daemon);}
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!("test daemon startup timeout")
    }
    fn endpoint(&self)->Result<Endpoint>{Ok(serde_json::from_slice(&opengate_security::secure_read(&self.dir.join("daemon.endpoint"))?)?)}
    async fn request(&self,command:LocalCommand)->Result<TcpStream>{
        let endpoint=self.endpoint()?;let mut stream=TcpStream::connect(endpoint.address).await?;
        write_frame(&mut stream,&LocalRequest{auth:endpoint.secret,command}).await?;Ok(stream)
    }
    async fn rpc(&self,command:LocalCommand)->Result<Reply>{
        let mut stream=self.request(command).await?;
        tokio::time::timeout(Duration::from_secs(60),read_frame(&mut stream)).await.context("local RPC timeout")?
    }
    async fn ok(&self,command:LocalCommand)->Result<serde_json::Value>{let reply=self.rpc(command).await?;reply.check()?;Ok(reply.data)}
    async fn open(&self,device:&str,request:RemoteRequest)->Result<TcpStream>{
        let mut stream=self.request(LocalCommand::Open{device:device.into(),request}).await?;
        let reply:Reply=tokio::time::timeout(Duration::from_secs(60),read_frame(&mut stream)).await??;reply.check()?;Ok(stream)
    }
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn pair_shell_files_forward_restart_and_revoke()->Result<()> {
    let temp=tempfile::tempdir()?;
    let a=Daemon::start(&temp.path().join("a"),None).await?;
    let mut b=Daemon::start(&temp.path().join("b"),None).await?;
    a.ok(LocalCommand::ConfigSet{key:"name".into(),value:"CLIENT-A".into()}).await?;
    b.ok(LocalCommand::ConfigSet{key:"name".into(),value:"HOST-B".into()}).await?;
    // Safe for CI running as root: explicit dual owner opt-in; isolated temporary state only.
    #[cfg(unix)] let root=unsafe {libc::geteuid()==0};
    #[cfg(not(unix))] let root=opengate_service::is_elevated();
    let permissions=if root {
        a.ok(LocalCommand::ConfigSet{key:"allow_admin".into(),value:"true".into()}).await?;
        b.ok(LocalCommand::ConfigSet{key:"allow_admin".into(),value:"true".into()}).await?;
        Permissions::full_admin()
    }else{Permissions::standard()};
    let allowed=b.ok(LocalCommand::Allow{permissions:permissions.clone(),ttl:900}).await?;
    let token=allowed["token"].as_str().context("token")?.to_owned();
    let paired=a.ok(LocalCommand::Pair{token:token.clone(),grant:permissions.clone()}).await?;
    let b_id=paired["device"]["peer_id"].as_str().context("peer id")?.to_owned();
    let a_id=a.ok(LocalCommand::Status).await?["device"]["peer_id"].as_str().context("peer id")?.to_owned();
    ensure!(!a.rpc(LocalCommand::Pair{token,grant:permissions.clone()}).await?.ok,"used token accepted twice");
    a.ok(LocalCommand::Connect{device:b_id.clone()}).await?;
    // Interactive programs run through a PTY, not a pre-canned command response.
    let mut shell=a.open(&b_id,RemoteRequest::Shell(ShellRequest::default())).await?;
    write_frame(&mut shell,&TerminalFrame::Resize{rows:35,cols:100}).await?;
    #[cfg(windows)] let command=b"echo OPENGATE_PTY_VERIFIED\r\nexit\r\n".to_vec();
    #[cfg(not(windows))] let command=b"printf 'OPENGATE_PTY_VERIFIED\\n'\nexit\n".to_vec();
    write_frame(&mut shell,&TerminalFrame::Input(command)).await?;
    let mut output=Vec::new();
    tokio::time::timeout(Duration::from_secs(20),async {
        loop {match read_frame::<TerminalFrame,_>(&mut shell).await?{TerminalFrame::Output(bytes)=>output.extend(bytes),TerminalFrame::Exit{..}=>break,_=>{}}}
        anyhow::Ok(())
    }).await??;
    ensure!(String::from_utf8_lossy(&output).contains("OPENGATE_PTY_VERIFIED"),"PTY output missing");
    // Multi-chunk push and pull over independent authenticated streams.
    let original=temp.path().join("source.bin");let received=temp.path().join("received.bin");
    let data:Vec<u8>=(0..1_048_577).map(|i|(i%251) as u8).collect();tokio::fs::write(&original,&data).await?;
    opengate_files::push(a.open(&b_id,RemoteRequest::Files).await?,&original,"payload.bin",false).await?;
    opengate_files::pull(a.open(&b_id,RemoteRequest::Files).await?,"payload.bin",&received,false).await?;
    ensure!(tokio::fs::read(&received).await?==data,"file integrity mismatch");
    let denied=opengate_files::request(a.open(&b_id,RemoteRequest::Files).await?,FileRequest::Stat{path:"../identity.key".into()}).await;
    ensure!(denied.is_err() || matches!(denied?,FileReply::Error(_)),"file traversal accepted");
    // Real TCP service through encrypted peer transport.
    let echo=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let target=echo.local_addr()?.to_string();
    let echo_task=tokio::spawn(async move {let (mut socket,_)=echo.accept().await?;let mut data=[0u8;8];socket.read_exact(&mut data).await?;socket.write_all(&data).await?;tokio::time::sleep(Duration::from_secs(60)).await;anyhow::Ok(())});
    let mut tunnel=a.open(&b_id,RemoteRequest::Tunnel{target,desktop:false}).await?;
    tunnel.write_all(b"OG-ECHO!").await?;let mut echoed=[0;8];tokio::time::timeout(Duration::from_secs(10),tunnel.read_exact(&mut echoed)).await??;ensure!(&echoed==b"OG-ECHO!","tunnel echo mismatch");
    // Downgrading permissions terminates already opened streams immediately.
    b.ok(LocalCommand::Permissions{device:a_id.clone(),permissions:Permissions::view_only()}).await?;
    let mut byte=[0u8;1];let end=tokio::time::timeout(Duration::from_secs(5),tunnel.read(&mut byte)).await?;ensure!(end.is_err() || end?==0,"permission downgrade left tunnel open");echo_task.abort();
    ensure!(!a.rpc(LocalCommand::Open{device:b_id.clone(),request:RemoteRequest::Shell(ShellRequest::default())}).await?.ok,"unauthorized shell permitted");
    b.ok(LocalCommand::Permissions{device:a_id.clone(),permissions}).await?;
    // Stop/restart the real peer process on its former port; preserve the state directory.
    let snapshot=b.ok(LocalCommand::Status).await?;
    let address=snapshot["network"]["listeners"][0].as_str().context("listener")?;
    let multi:libp2p::Multiaddr=address.parse()?;
    let port=multi.iter().find_map(|p|if let libp2p::multiaddr::Protocol::Udp(port)=p{Some(port)}else{None}).context("QUIC port")?;
    b.child.kill()?;b.child.wait()?;tokio::time::sleep(Duration::from_millis(200)).await;
    b=Daemon::start(&b.dir,Some(port)).await?;
    tokio::time::timeout(Duration::from_secs(60),async {
        loop {if a.rpc(LocalCommand::Connect{device:b_id.clone()}).await.is_ok_and(|r|r.ok){break;}tokio::time::sleep(Duration::from_secs(1)).await;}
    }).await.context("saved peer did not reconnect after daemon restart")?;
    b.ok(LocalCommand::Revoke{device:a_id}).await?;
    ensure!(!a.rpc(LocalCommand::Connect{device:b_id}).await?.ok,"revoked peer authenticated");
    Ok(())
}

#[tokio::test]
async fn local_api_rejects_wrong_credential()->Result<()> {
    let temp=tempfile::tempdir()?;let daemon=Daemon::start(temp.path(),None).await?;
    let endpoint=daemon.endpoint()?;let mut stream=TcpStream::connect(endpoint.address).await?;
    write_frame(&mut stream,&LocalRequest{auth:"incorrect".into(),command:LocalCommand::Allow{permissions:Permissions::full_admin(),ttl:900}}).await?;
    let mut data=[0u8;1];let result=tokio::time::timeout(Duration::from_secs(2),stream.read(&mut data)).await?;
    ensure!(result.is_err()||result?==0,"unauthorized local API request accepted");Ok(())
}
