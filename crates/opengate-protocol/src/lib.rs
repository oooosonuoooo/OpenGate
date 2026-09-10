//! Bounded, versioned OpenGate framing over mutually authenticated encrypted streams.
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const VERSION: u16 = 1;
pub const MAX_MESSAGE: usize = 1024 * 1024;
pub const CHUNK_SIZE: usize = 64 * 1024;
pub const CONTROL: &str = "/opengate/control/1";
pub const TERMINAL: &str = "/opengate/terminal/1";
pub const FILES: &str = "/opengate/files/1";
pub const TUNNEL: &str = "/opengate/tcp-forward/1";
pub const DESKTOP: &str = "/opengate/desktop/1";
pub const CLIPBOARD: &str = "/opengate/clipboard/1";

/// Every frame carries magic, version, message type, unique request ID and length.
/// Type 1 is the structured CBOR envelope, whose tagged enum identifies its operation.
pub async fn write_frame<T: Serialize, W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &T,
) -> Result<()> {
    write_frame_with_id(writer, Uuid::new_v4(), value).await
}

pub async fn write_frame_with_id<T: Serialize, W: AsyncWrite + Unpin>(
    writer: &mut W,
    id: Uuid,
    value: &T,
) -> Result<()> {
    let mut payload = Vec::new();
    ciborium::into_writer(value, &mut payload)?;
    ensure!(payload.len() <= MAX_MESSAGE, "message exceeds size limit");
    let mut header = [0u8; 28];
    header[..4].copy_from_slice(b"OGTE");
    header[4..6].copy_from_slice(&VERSION.to_be_bytes());
    header[6..8].copy_from_slice(&1u16.to_be_bytes());
    header[8..24].copy_from_slice(id.as_bytes());
    header[24..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<T: DeserializeOwned, R: AsyncRead + Unpin>(reader: &mut R) -> Result<T> {
    let mut header = [0u8; 28];
    reader.read_exact(&mut header).await?;
    ensure!(&header[..4] == b"OGTE", "invalid OpenGate frame");
    ensure!(
        u16::from_be_bytes([header[4], header[5]]) == VERSION,
        "incompatible OpenGate protocol version; upgrade required"
    );
    ensure!(
        u16::from_be_bytes([header[6], header[7]]) == 1,
        "unsupported message type"
    );
    let length = u32::from_be_bytes([header[24], header[25], header[26], header[27]]) as usize;
    ensure!(
        length > 0 && length <= MAX_MESSAGE,
        "invalid message length"
    );
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    // A finite cursor and ciborium's recursion limit bound malformed input work.
    let mut cursor = std::io::Cursor::new(&bytes);
    let value = ciborium::from_reader(&mut cursor)?;
    ensure!(
        cursor.position() == length as u64,
        "trailing bytes in message"
    );
    Ok(value)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    pub terminal: bool,
    pub files: bool,
    pub tcp_forward: bool,
    pub desktop: bool,
    pub clipboard: bool,
    pub full_admin: bool,
}
impl Permissions {
    pub fn view_only() -> Self {
        Self::default()
    }
    pub fn standard() -> Self {
        Self {
            terminal: true,
            files: true,
            tcp_forward: true,
            desktop: true,
            ..Self::default()
        }
    }
    pub fn full_admin() -> Self {
        Self {
            full_admin: true,
            ..Self::standard()
        }
    }
    pub fn preset(name: &str) -> Result<Self> {
        match name {
            "view-only" => Ok(Self::view_only()),
            "standard" => Ok(Self::standard()),
            "full-admin" => Ok(Self::full_admin()),
            _ => bail!("unknown preset; use view-only, standard or full-admin"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerHello {
    pub peer_id: String,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub device_id: String,
    pub name: String,
    pub os: String,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellRequest {
    pub shell: Option<String>,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub rows: u16,
    pub cols: u16,
}
impl Default for ShellRequest {
    fn default() -> Self {
        Self {
            shell: None,
            cwd: None,
            env: BTreeMap::new(),
            rows: 24,
            cols: 80,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TerminalFrame {
    Input(#[serde(with = "serde_bytes")] Vec<u8>),
    Output(#[serde(with = "serde_bytes")] Vec<u8>),
    Resize { rows: u16, cols: u16 },
    Exit { code: u32 },
    Close,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileRequest {
    List {
        path: String,
    },
    Mkdir {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Copy {
        from: String,
        to: String,
    },
    Delete {
        path: String,
        recursive: bool,
    },
    Stat {
        path: String,
    },
    Download {
        path: String,
        offset: u64,
    },
    Upload {
        path: String,
        size: u64,
        sha256: String,
        overwrite: bool,
    },
    SetPermissions {
        path: String,
        mode: u32,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileReply {
    Ok,
    Error(String),
    Entries(Vec<FileEntry>),
    Metadata(FileEntry),
    Ready {
        offset: u64,
        size: u64,
        sha256: String,
    },
    Chunk {
        offset: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    Complete {
        sha256: String,
    },
}

// Pairing secrets intentionally never implement Debug, to prevent accidental logging.
#[derive(Clone, Serialize, Deserialize)]
pub enum RemoteRequest {
    Pair { secret: String, hello: PeerHello },
    Authenticate { hello: PeerHello },
    Shell(ShellRequest),
    Files,
    Tunnel { target: String, desktop: bool },
    ClipboardGet,
    ClipboardSet { text: String },
}
impl RemoteRequest {
    pub fn protocol(&self) -> &'static str {
        match self {
            Self::Pair { .. } | Self::Authenticate { .. } => CONTROL,
            Self::Shell(_) => TERMINAL,
            Self::Files => FILES,
            Self::Tunnel { desktop: true, .. } => DESKTOP,
            Self::Tunnel { .. } => TUNNEL,
            Self::ClipboardGet | Self::ClipboardSet { .. } => CLIPBOARD,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct OpenRequest {
    pub request_id: Uuid,
    pub request: RemoteRequest,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    pub error: Option<String>,
    #[serde(default)]
    pub retryable: bool,
    pub data: serde_json::Value,
}
impl Reply {
    pub fn success<T: Serialize>(value: T) -> Result<Self> {
        Ok(Self {
            ok: true,
            error: None,
            retryable: false,
            data: serde_json::to_value(value)?,
        })
    }
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(message.into()),
            retryable: false,
            data: serde_json::Value::Null,
        }
    }
    pub fn into_value<T: DeserializeOwned>(self) -> Result<T> {
        self.check()?;
        Ok(serde_json::from_value(self.data)?)
    }
    pub fn from_error(error: &anyhow::Error) -> Self {
        let mut reply = Self::failure(error.to_string());
        reply.retryable = error.chain().any(|cause| {
            cause.downcast_ref::<std::io::Error>().is_some_and(|e| {
                matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::BrokenPipe
                )
            }) || cause
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some()
        });
        reply
    }
    pub fn check(&self) -> Result<()> {
        if !self.ok && self.retryable {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                self.error
                    .clone()
                    .unwrap_or_else(|| "connection unavailable".into()),
            )
            .into());
        }
        ensure!(
            self.ok,
            "{}",
            self.error.as_deref().unwrap_or("operation rejected")
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LocalRequest {
    pub auth: String,
    pub command: LocalCommand,
}
#[derive(Clone, Serialize, Deserialize)]
pub enum LocalCommand {
    Status,
    Allow {
        permissions: Permissions,
        ttl: u64,
    },
    CancelPairing,
    Pair {
        token: String,
        grant: Permissions,
    },
    Connect {
        device: String,
    },
    Devices,
    Rename {
        device: String,
        name: String,
    },
    Revoke {
        device: String,
    },
    Permissions {
        device: String,
        permissions: Permissions,
    },
    Open {
        device: String,
        request: RemoteRequest,
    },
    Logs {
        limit: usize,
    },
    ConfigGet,
    ConfigSet {
        key: String,
        value: String,
    },
    Shutdown,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn roundtrip() -> Result<()> {
        let mut bytes = Vec::new();
        let p = Permissions::standard();
        write_frame(&mut bytes, &p).await?;
        let decoded: Permissions = read_frame(&mut bytes.as_slice()).await?;
        assert_eq!(p, decoded);
        Ok(())
    }
    #[tokio::test]
    async fn malformed_headers_rejected_before_allocation() -> Result<()> {
        for (version, length) in [(2, 8), (1, u32::MAX), (1, 0)] {
            let mut header = [0u8; 28];
            header[..4].copy_from_slice(b"OGTE");
            header[4..6].copy_from_slice(&(version as u16).to_be_bytes());
            header[6..8].copy_from_slice(&1u16.to_be_bytes());
            header[24..].copy_from_slice(&length.to_be_bytes());
            assert!(
                read_frame::<Permissions, _>(&mut header.as_slice())
                    .await
                    .is_err()
            );
        }
        Ok(())
    }
    #[tokio::test]
    async fn excessive_messages_rejected() {
        let mut bytes = Vec::new();
        assert!(
            write_frame(&mut bytes, &vec![0u8; MAX_MESSAGE + 1])
                .await
                .is_err()
        );
    }
}
