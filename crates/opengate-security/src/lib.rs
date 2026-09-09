//! Local identity and short-lived pairing credentials.
//!
//! The pairing code is deliberately an enrolment secret only.  It is never used
//! to derive the persistent libp2p identity used after pairing.

use anyhow::{anyhow, bail, Context, Result};
use data_encoding::BASE32_NOPAD;
use fs2::FileExt;
use libp2p::{identity, PeerId};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const IDENTITY_FILE: &str = "identity.key";
const DEVICE_ID_FILE: &str = "device-id";
const LOCK_FILE: &str = ".identity.lock";
const MAX_TOKEN_AGE: u64 = 60 * 60;
const MAX_ADDRESSES: usize = 16;
const MAX_ADDRESS_LEN: usize = 512;
const MAX_TOKEN_LEN: usize = 16 * 1024;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Persistent, installation-specific libp2p identity.
pub struct Identity {
    pub keypair: identity::Keypair,
    pub device_id: Uuid,
}

impl Identity {
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        ensure_private_dir(dir)?;
        let lock = lock_dir(dir)?;
        let _guard = FileLock(lock);

        let key_path = dir.join(IDENTITY_FILE);
        let device_path = dir.join(DEVICE_ID_FILE);
        let keypair = if key_path.exists() {
            let encoded = secure_read(&key_path)?;
            identity::Keypair::from_protobuf_encoding(&encoded)
                .context("stored OpenGate identity key is invalid")?
        } else {
            let keypair = identity::Keypair::generate_ed25519();
            let encoded = Zeroizing::new(keypair.to_protobuf_encoding()?);
            secure_write(&key_path, &encoded)?;
            keypair
        };
        let device_id = if device_path.exists() {
            let stored = secure_read(&device_path)?;
            std::str::from_utf8(&stored)
                .context("stored device id is not UTF-8")?
                .trim()
                .parse()
                .context("stored device id is invalid")?
        } else {
            let id = Uuid::new_v4();
            secure_write(&device_path, id.to_string().as_bytes())?;
            id
        };
        Ok(Self { keypair, device_id })
    }

    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }
}

/// A self-contained, single-use pairing credential. Debug output never exposes the secret.
#[derive(Clone, Serialize, Deserialize)]
pub struct PairingToken {
    pub version: u16,
    pub peer_id: String,
    pub secret: String,
    pub expires_at: u64,
    pub addresses: Vec<String>,
}

impl fmt::Debug for PairingToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingToken")
            .field("version", &self.version)
            .field("peer_id", &self.peer_id)
            .field("secret", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("addresses", &self.addresses)
            .finish()
    }
}

impl PairingToken {
    pub fn generate(peer_id: String, addresses: Vec<String>, ttl_seconds: u64) -> Result<Self> {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let token = Self {
            version: 1,
            peer_id,
            secret: BASE32_NOPAD.encode(&bytes),
            expires_at: now().checked_add(ttl_seconds).ok_or_else(|| anyhow!("token expiry overflow"))?,
            addresses,
        };
        token.validate(Some(ttl_seconds))?;
        Ok(token)
    }

    pub fn encode(&self) -> Result<String> {
        self.validate(None)?;
        let payload = serde_json::to_vec(self)?;
        if payload.len() > MAX_TOKEN_LEN { bail!("pairing token is too large"); }
        let mut checksum = Sha256::digest(&payload)[..4].to_vec();
        let encoded = BASE32_NOPAD.encode(&payload);
        let check = BASE32_NOPAD.encode(&checksum.split_off(0));
        Ok(format!("OG1-{}-{}", group(&encoded), group(&check)))
    }

    pub fn decode(input: &str) -> Result<Self> {
        let compact: String = input.chars().filter(|c| *c != '-' && !c.is_whitespace()).collect();
        let raw = compact.strip_prefix("OG1").ok_or_else(|| anyhow!("invalid OpenGate pairing code prefix"))?;
        if raw.len() < 9 || raw.len() > MAX_TOKEN_LEN * 2 { bail!("invalid pairing code length"); }
        let (payload_encoded, checksum_encoded) = raw.split_at(raw.len() - 7);
        let payload = BASE32_NOPAD.decode(payload_encoded.as_bytes()).context("invalid pairing code")?;
        let expected = BASE32_NOPAD.encode(&Sha256::digest(&payload)[..4]);
        if checksum_encoded != expected { bail!("pairing code checksum does not match"); }
        let token: Self = serde_json::from_slice(&payload).context("invalid pairing code payload")?;
        token.validate(None)?;
        Ok(token)
    }

    pub fn secret_hash(&self) -> String {
        hex::encode(Sha256::digest(self.secret.as_bytes()))
    }

    fn validate(&self, requested_ttl: Option<u64>) -> Result<()> {
        if self.version != 1 { bail!("unsupported pairing token version"); }
        self.peer_id.parse::<PeerId>().context("invalid pairing peer id")?;
        let secret = BASE32_NOPAD.decode(self.secret.as_bytes()).context("invalid pairing secret")?;
        if secret.len() != 32 { bail!("pairing secret must contain 256 bits of entropy"); }
        let current = now();
        if self.expires_at <= current { bail!("pairing token has expired"); }
        let remaining = self.expires_at - current;
        if remaining > MAX_TOKEN_AGE || requested_ttl.is_some_and(|ttl| ttl == 0 || ttl > MAX_TOKEN_AGE) {
            bail!("pairing token lifetime must be between 1 and {MAX_TOKEN_AGE} seconds");
        }
        if self.addresses.is_empty() || self.addresses.len() > MAX_ADDRESSES { bail!("pairing token must contain 1 to {MAX_ADDRESSES} addresses"); }
        for address in &self.addresses {
            if address.is_empty() || address.len() > MAX_ADDRESS_LEN { bail!("invalid pairing address length"); }
            address.parse::<libp2p::Multiaddr>().context("invalid pairing multiaddress")?;
        }
        Ok(())
    }
}

fn group(value: &str) -> String {
    value.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

pub fn secure_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow!("protected file has no parent"))?;
    ensure_private_dir(parent)?;
    reject_symlink(path)?;
    if fs::symlink_metadata(path).is_ok() { check_private_file(path)?; }
    #[cfg(windows)]
    let protected = windows_protect(contents)?;
    #[cfg(not(windows))]
    let protected = contents.to_vec();
    atomic_private_write(path, &protected)
}

pub fn secure_read(path: &Path) -> Result<Vec<u8>> {
    check_private_file(path)?;
    let mut data = Zeroizing::new(Vec::new());
    File::open(path)?.read_to_end(&mut data)?;
    #[cfg(windows)]
    return windows_unprotect(&data);
    #[cfg(not(windows))]
    Ok(data.to_vec())
}

fn lock_dir(dir: &Path) -> Result<File> {
    let path = dir.join(LOCK_FILE);
    reject_symlink(&path)?;
    let file = OpenOptions::new().read(true).write(true).create(true).open(&path)?;
    set_private_file_mode(&file)?;
    file.lock_exclusive()?;
    Ok(file)
}

struct FileLock(File);
impl Drop for FileLock { fn drop(&mut self) { let _ = self.0.unlock(); } }

fn atomic_private_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().expect("checked parent");
    let nonce = Uuid::new_v4();
    let temp = parent.join(format!(".{}.{}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("secret"), nonce));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temp)?;
        set_private_file_mode(&file)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        sync_parent(parent)?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temp); }
    result
}

#[cfg(unix)]
fn ensure_private_dir(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_err() { fs::create_dir_all(path)?; }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() { bail!("protected path is not a real directory"); }
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.uid() != unsafe { libc::geteuid() } { bail!("protected directory is not owned by this user"); }
    if metadata.permissions().mode() & 0o077 != 0 { fs::set_permissions(path, fs::Permissions::from_mode(0o700))?; }
    Ok(())
}
#[cfg(not(unix))]
fn ensure_private_dir(path: &Path) -> Result<()> { fs::create_dir_all(path)?; Ok(()) }

fn reject_symlink(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() { bail!("refusing symlink for protected file"); }
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_private_file_mode(_file: &File) -> Result<()> { Ok(()) }

#[cfg(unix)]
fn check_private_file(path: &Path) -> Result<()> {
    reject_symlink(path)?;
    let metadata = fs::metadata(path).with_context(|| format!("missing protected file {}", path.display()))?;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        bail!("protected file has unsafe ownership or permissions");
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_private_file(path: &Path) -> Result<()> { reject_symlink(path)?; Ok(()) }

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> { File::open(path)?.sync_all()?; Ok(()) }
#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<()> { Ok(()) }

#[cfg(windows)]
fn windows_protect(input: &[u8]) -> Result<Vec<u8>> { dpapi(input, true) }
#[cfg(windows)]
fn windows_unprotect(input: &[u8]) -> Result<Vec<u8>> { dpapi(input, false) }
#[cfg(windows)]
fn dpapi(input: &[u8], protect: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB}};
    let mut input_blob = CRYPT_INTEGER_BLOB { cbData: input.len() as u32, pbData: input.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe {
        if protect { CryptProtectData(&mut input_blob, std::ptr::null(), std::ptr::null(), 0, std::ptr::null(), 0, &mut output) }
        else { CryptUnprotectData(&mut input_blob, std::ptr::null_mut(), std::ptr::null(), 0, std::ptr::null(), 0, &mut output) }
    };
    if ok == 0 { bail!("Windows DPAPI operation failed"); }
    let result = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData.cast()); }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn identity_is_persistent_and_private() {
        let dir = tempdir().unwrap();
        let one = Identity::load_or_create(dir.path()).unwrap();
        let two = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(one.peer_id(), two.peer_id()); assert_eq!(one.device_id, two.device_id);
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; assert_eq!(fs::metadata(dir.path().join(IDENTITY_FILE)).unwrap().permissions().mode() & 0o777, 0o600); }
    }
    #[test]
    fn pairing_code_roundtrip_checksum_and_expiry() {
        let id = identity::Keypair::generate_ed25519().public().to_peer_id().to_string();
        let token = PairingToken::generate(id, vec!["/ip4/127.0.0.1/udp/44344/quic-v1".into()], 60).unwrap();
        let code = token.encode().unwrap();
        assert_eq!(PairingToken::decode(&code).unwrap().secret_hash(), token.secret_hash());
        let mut broken = code.into_bytes();
        let last = broken.len() - 1; broken[last] = if broken[last] == b'A' { b'B' } else { b'A' };
        assert!(PairingToken::decode(std::str::from_utf8(&broken).unwrap()).is_err());
        let expired = PairingToken { expires_at: 1, ..token }; assert!(expired.encode().is_err());
    }
}
