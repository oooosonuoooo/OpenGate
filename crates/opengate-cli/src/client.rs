use std::{path::{Path,PathBuf},process::Stdio,time::Duration};
use anyhow::{Context, Result, bail, ensure};
use opengate_protocol::*;
use tokio::net::{TcpListener,TcpStream};

pub async fn rpc(dir:&Path,command:LocalCommand)->Result<Reply> {
    let mut stream=local_stream(dir,command).await?;
    let reply:Reply=tokio::time::timeout(Duration::from_secs(90),read_frame(&mut stream)).await??;
    reply.check()?;Ok(reply)
}

async fn local_stream(dir:&Path,command:LocalCommand)->Result<TcpStream> {
    let endpoint=ensure_daemon(dir).await?;
    let mut stream=TcpStream::connect(&endpoint.address).await?;
    write_frame(&mut stream,&LocalRequest{auth:endpoint.secret,command}).await?;
    Ok(stream)
}

pub async fn open(dir:&Path,device:&str,request:RemoteRequest)->Result<TcpStream> {
    let mut stream=local_stream(dir,LocalCommand::Open{device:device.into(),request}).await?;
    let reply:Reply=tokio::time::timeout(Duration::from_secs(90),read_frame(&mut stream)).await??;
    reply.check()?;
    Ok(stream)
}

pub async fn ensure_daemon(dir:&Path)->Result<crate::daemon::Endpoint> {
    if let Ok(endpoint)=crate::daemon::endpoint(dir) {
        if tokio::time::timeout(Duration::from_millis(300),TcpStream::connect(&endpoint.address)).await.is_ok_and(|r|r.is_ok()) {return Ok(endpoint);}
    }
    opengate_security::Identity::load_or_create(dir)?;
    let executable=std::env::current_exe()?;
    let mut command=tokio::process::Command::new(executable);
    command.arg("--data-dir").arg(dir).arg("daemon").stdin(Stdio::null()).stdout(Stdio::null());
    let log=std::fs::OpenOptions::new().create(true).append(true).open(dir.join("daemon.log"))?;
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;log.set_permissions(std::fs::Permissions::from_mode(0o600))?;}
    command.stderr(Stdio::from(log));
    #[cfg(windows)] {command.creation_flags(0x08000000);}
    let mut child=command.spawn().context("unable to start OpenGate daemon")?;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(endpoint)=crate::daemon::endpoint(dir) {
            if tokio::time::timeout(Duration::from_millis(100),TcpStream::connect(&endpoint.address)).await.is_ok_and(|r|r.is_ok()) {return Ok(endpoint);}
        }
        if let Some(status)=child.try_wait()? {bail!("daemon exited ({status}); inspect {}/daemon.log",dir.display());}
    }
    bail!("daemon startup timed out; inspect {}/daemon.log",dir.display())
}

pub async fn shell(dir:&Path,device:&str,mut request:ShellRequest,command:Option<String>)->Result<()> {
    if let Ok((cols,rows))=crossterm::terminal::size(){request.cols=cols;request.rows=rows;}
    let mut stream=open(dir,device,RemoteRequest::Shell(request.clone())).await?;
    if let Some(command)=command {
        write_frame(&mut stream,&TerminalFrame::Input(format!("{command}\nexit\n").into_bytes())).await?;
        loop {
            match read_frame(&mut stream).await? {
                TerminalFrame::Output(data)=>{use std::io::Write;std::io::stdout().write_all(&data)?;std::io::stdout().flush()?;},
                TerminalFrame::Exit{code}=>{ensure!(code==0,"remote shell exited with code {code}");break;},
                _=>{},
            }
        }Ok(())
    } else {eprintln!("OpenGate Secure Shell — encrypted, authenticated: {device}");opengate_terminal::client(stream,request).await}
}

pub async fn file_request(dir:&Path,device:&str,request:FileRequest)->Result<FileReply> {
    let stream=open(dir,device,RemoteRequest::Files).await?;
    let reply=opengate_files::request(stream,request).await?;
    if let FileReply::Error(message)=&reply {bail!("{message}");}
    Ok(reply)
}

pub async fn transfer(dir:&Path,device:&str,source:&str,destination:&str,push:bool,overwrite:bool,resume:bool)->Result<()> {
    // Directory recursion uses separate streams per file; never buffers the tree contents.
    if push && Path::new(source).is_dir() {
        file_request(dir,device,FileRequest::Mkdir{path:destination.into()}).await?;
        let mut pending=vec![(PathBuf::from(source),destination.to_string())];
        while let Some((local,remote))=pending.pop() {
            let mut entries=tokio::fs::read_dir(local).await?;
            while let Some(entry)=entries.next_entry().await? {
                let kind=entry.file_type().await?;
                ensure!(!kind.is_symlink(),"directory upload does not follow symlinks");
                let name=entry.file_name().into_string().map_err(|_|anyhow::anyhow!("filename is not UTF-8"))?;
                let target=format!("{}/{name}",remote.trim_end_matches('/'));
                if kind.is_dir() {file_request(dir,device,FileRequest::Mkdir{path:target.clone()}).await?;pending.push((entry.path(),target));}
                else if kind.is_file() {transfer_file(dir,device,&entry.path().to_string_lossy(),&target,true,overwrite,resume).await?;}
            }
        }return Ok(());
    }
    if !push {
        let metadata=file_request(dir,device,FileRequest::Stat{path:source.into()}).await?;
        if matches!(metadata,FileReply::Metadata(ref entry) if entry.is_dir) {
            tokio::fs::create_dir_all(destination).await?;
            let mut pending=vec![(source.to_string(),PathBuf::from(destination))];
            while let Some((remote,local))=pending.pop(){
                let FileReply::Entries(entries)=file_request(dir,device,FileRequest::List{path:remote.clone()}).await? else {bail!("invalid directory listing")};
                for entry in entries {
                    // A remote peer cannot write paths outside the selected download tree.
                    ensure!(!entry.name.is_empty() && entry.name!="." && entry.name!=".." && !entry.name.contains(['/', '\\', ':']) && !entry.name.chars().any(char::is_control),"unsafe remote filename");
                    let source=format!("{}/{name}",remote.trim_end_matches('/'),name=entry.name);
                    let target=local.join(entry.name);
                    ensure!(!target.is_symlink(),"refusing local destination symlink");
                    if entry.is_dir {tokio::fs::create_dir_all(&target).await?;pending.push((source,target));}
                    else {transfer_file(dir,device,&source,&target.to_string_lossy(),false,overwrite,resume).await?;}
                }
            }return Ok(());
        }
    }
    transfer_file(dir,device,source,destination,push,overwrite,resume).await
}

async fn transfer_file(dir:&Path,device:&str,source:&str,destination:&str,push:bool,overwrite:bool,resume:bool)->Result<()> {
    let mut retry=0usize;
    loop {
        let result=async {
            let stream=open(dir,device,RemoteRequest::Files).await?;
            if push {opengate_files::push(stream,Path::new(source),destination,overwrite).await}
            else {opengate_files::pull(stream,source,Path::new(destination),overwrite).await}
        }.await;
        match result {
            Ok(())=>return Ok(()),
            Err(error)=>{
                let transient=error.chain().any(|cause|cause.downcast_ref::<std::io::Error>().is_some() || cause.downcast_ref::<tokio::time::error::Elapsed>().is_some());
                // Authorization, path and checksum errors are terminal; commands are never replayed.
                if !resume || !transient {return Err(error);}
                let seconds=[1,2,4,8,15,30,60][retry.min(6)];retry+=1;
                eprintln!("Transfer interrupted; reconnecting in {seconds}s. Verified partial data will be resumed.");
                tokio::select! {_=tokio::time::sleep(Duration::from_secs(seconds))=>{},_=tokio::signal::ctrl_c()=>bail!("transfer cancelled; checkpoint retained")}
            }
        }
    }
}

pub fn bind_address(value:&str,allow_public:bool)->Result<std::net::SocketAddr> {
    let address=if let Ok(port)=value.parse::<u16>() {std::net::SocketAddr::from(([127,0,0,1],port))} else {value.parse()?};
    ensure!(address.ip().is_loopback() || allow_public,"public proxy bind requires --acknowledge-public-bind");Ok(address)
}

pub async fn forward(dir:PathBuf,device:String,local:String,remote:String,desktop:bool,allow_public:bool,socks:bool)->Result<()> {
    let address=bind_address(&local,allow_public)?;
    let listener=TcpListener::bind(address).await?;
    eprintln!("OpenGate {} listening on {} → {} {}",if socks {"SOCKS5"} else if desktop {"desktop tunnel"} else {"TCP tunnel"},listener.local_addr()?,device,remote);
    let limit=std::sync::Arc::new(tokio::sync::Semaphore::new(64));
    let mut sessions=tokio::task::JoinSet::new();
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
    sessions.abort_all();Ok(())
}
