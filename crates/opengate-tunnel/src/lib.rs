//! TCP forwarding primitives carried by an already authenticated OpenGate stream.
//!
//! This crate deliberately owns no listener or authorization state.  The daemon
//! authorizes a target before handing a stream to `serve_with_policy`.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result, anyhow, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

/// Connect an authenticated stream to a loopback TCP service and relay bytes.
pub async fn serve<S>(stream: S, target: &str, cancel: CancellationToken) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_with_policy(stream, target, false, cancel).await
}

/// Connect an authenticated stream to `target` and relay bytes until either side
/// closes. Non-loopback targets require an explicit daemon policy decision.
pub async fn serve_with_policy<S>(
    mut stream: S,
    target: &str,
    allow_non_loopback: bool,
    cancel: CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let targets = resolve_target(target, allow_non_loopback).await?;
    let mut tcp = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        connected = TcpStream::connect(targets.as_slice()) => connected.with_context(|| format!("connecting to {target}"))?,
    };
    tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        result = tokio::io::copy_bidirectional(&mut stream, &mut tcp) => {
            result.context("relaying TCP tunnel")?;
            Ok(())
        }
    }
}

async fn resolve_target(target: &str, allow_non_loopback: bool) -> Result<Vec<SocketAddr>> {
    let (host, port) = split_target(target)?;
    if port == 0 {
        bail!("target port must be non-zero");
    }
    let targets = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| format!("resolving tunnel target {host}"))?
            .collect::<Vec<_>>()
    };
    ensure!(!targets.is_empty(), "target resolved to no addresses");
    if !allow_non_loopback && targets.iter().any(|addr| !addr.ip().is_loopback()) {
        bail!("non-loopback tunnel targets require an explicit policy grant");
    }
    Ok(targets)
}

fn split_target(target: &str) -> Result<(String, u16)> {
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("target must be host:port"))?;
    if host.is_empty() || host.contains('[') || host.contains(']') {
        bail!("invalid tunnel target");
    }
    Ok((host.to_owned(), port.parse().context("invalid target port")?))
}

/// Negotiate a SOCKS5 no-auth CONNECT request and return its requested target.
/// The caller remains responsible for binding its SOCKS listener to localhost and
/// authorizing the eventual OpenGate connection.
pub async fn negotiate<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0_u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .context("reading SOCKS greeting")?;
    if greeting[0] != 5 || greeting[1] == 0 {
        bail!("unsupported SOCKS greeting");
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await?;
        bail!("SOCKS client does not offer no-authentication");
    }
    stream.write_all(&[5, 0]).await?;

    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("reading SOCKS request")?;
    if header[0] != 5 || header[1] != 1 || header[2] != 0 {
        reply(stream, false).await?;
        bail!("only SOCKS5 CONNECT is supported");
    }
    let host = match header[3] {
        1 => {
            let mut raw = [0_u8; 4];
            stream.read_exact(&mut raw).await?;
            std::net::Ipv4Addr::from(raw).to_string()
        }
        4 => {
            let mut raw = [0_u8; 16];
            stream.read_exact(&mut raw).await?;
            format!("[{}]", std::net::Ipv6Addr::from(raw))
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            if len == 0 || len > 253 {
                reply(stream, false).await?;
                bail!("invalid SOCKS domain length");
            }
            let mut raw = vec![0; len];
            stream.read_exact(&mut raw).await?;
            let name = std::str::from_utf8(&raw).context("SOCKS domain is not UTF-8")?;
            if name.contains('\0') {
                bail!("invalid SOCKS domain");
            }
            name.to_owned()
        }
        _ => {
            reply(stream, false).await?;
            bail!("unsupported SOCKS address type");
        }
    };
    let port = stream.read_u16().await?;
    if port == 0 {
        bail!("SOCKS target port must be non-zero");
    }
    Ok(format!("{host}:{port}"))
}

/// Send a SOCKS5 CONNECT response with an unspecified bound address.
pub async fn reply<S>(stream: &mut S, success: bool) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let code = if success { 0 } else { 1 };
    stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn only_loopback_is_default() {
        assert!(resolve_target("127.0.0.1:80", false).await.is_ok());
        assert!(resolve_target("[::1]:80", false).await.is_ok());
        assert!(resolve_target("8.8.8.8:53", false).await.is_err());
    }

    #[tokio::test]
    async fn relays_a_real_tcp_connection() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let target = listener.local_addr()?.to_string();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            let mut b = [0; 4];
            socket.read_exact(&mut b).await?;
            socket.write_all(&b).await?;
            Ok::<(), anyhow::Error>(())
        });
        let (server, mut client) = tokio::io::duplex(4096);
        let cancel = CancellationToken::new();
        let service_cancel = cancel.clone();
        let service = tokio::spawn(async move { serve(server, &target, service_cancel).await });
        client.write_all(b"ping").await?;
        let mut b = [0; 4];
        client.read_exact(&mut b).await?;
        assert_eq!(&b, b"ping");
        cancel.cancel();
        service.await??;
        echo.await??;
        Ok(())
    }
}
