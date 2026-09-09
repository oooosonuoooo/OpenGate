//! Persistent daemon configuration and the local trust database.
use anyhow::{anyhow, bail, Context, Result};
pub use opengate_protocol::Permissions;
use opengate_security::{now, PairingToken};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}};
use uuid::Uuid;

const CONFIG_FILE: &str = "config.toml";
const DB_FILE: &str = "opengate.sqlite3";
const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub name: String,
    pub listen: Vec<String>,
    pub relay_nodes: Vec<String>,
    pub bootstrap_nodes: Vec<String>,
    pub allow_pairing: bool,
    pub allow_admin: bool,
    pub file_root: PathBuf,
    pub max_connections: u32,
    pub max_streams: usize,
    pub reconnect: bool,
}

impl Default for Config {
    fn default() -> Self {
        let name = std::env::var("COMPUTERNAME")
            .ok()
            .or_else(|| fs::read_to_string("/etc/hostname").ok())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .unwrap_or_else(|| "OpenGate".into());
        Self {
            name,
            listen: vec![
                "/ip4/0.0.0.0/udp/44344/quic-v1".into(),
                "/ip4/0.0.0.0/tcp/44344".into(),
            ],
            relay_nodes: vec![], bootstrap_nodes: vec![], allow_pairing: true, allow_admin: false,
            file_root: PathBuf::from("shared"), max_connections: 32, max_streams: 16, reconnect: true,
        }
    }
}

impl Config {
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join(CONFIG_FILE);
        if path.exists() {
            let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            let mut config: Self = toml::from_str(&text).context("invalid OpenGate config")?;
            if config.file_root.is_relative() { config.file_root = dir.join(&config.file_root); }
            config.validate()?;
            Ok(config)
        } else {
            let mut config = Self::default();
            config.file_root = dir.join(&config.file_root);
            config.save(dir)?;
            fs::create_dir_all(&config.file_root)?;
            Ok(config)
        }
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let mut persisted = self.clone();
        if let Ok(relative) = self.file_root.strip_prefix(dir) { persisted.file_root = relative.to_path_buf(); }
        persisted.validate()?;
        fs::create_dir_all(dir)?;
        let path = dir.join(CONFIG_FILE);
        let temp = dir.join(format!(".{CONFIG_FILE}.{}.tmp", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            fs::write(&temp, toml::to_string_pretty(&persisted)?)?;
            fs::rename(&temp, &path)?;
            Ok(())
        })();
        if result.is_err() { let _ = fs::remove_file(temp); }
        result
    }

    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.name.len() > 128 { bail!("device name must be 1 to 128 characters"); }
        if self.listen.is_empty() || self.listen.len() > 16 { bail!("listen addresses must contain 1 to 16 entries"); }
        for listen in &self.listen { listen.parse::<libp2p::Multiaddr>().context("invalid listen multiaddress")?; }
        if self.max_connections == 0 || self.max_connections > 10_000 || self.max_streams == 0 || self.max_streams > 1_024 { bail!("connection limits are out of range"); }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub peer_id: String,
    pub public_key: Vec<u8>,
    pub device_id: String,
    pub name: String,
    pub os: String,
    pub permissions: Permissions,
    pub addresses: Vec<String>,
    pub paired_at: u64,
    pub last_connected: Option<u64>,
    pub trusted: bool,
}

/// A cloneable, path-backed store. Each operation opens a short-lived SQLite connection.
#[derive(Debug, Clone)]
pub struct Store { path: PathBuf }

impl Store {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let store = Self { path: dir.join(DB_FILE) };
        let mut connection = store.connection()?;
        store.migrate(&mut connection)?;
        Ok(store)
    }

    pub fn devices(&self) -> Result<Vec<Device>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT peer_id, public_key, device_id, name, os, permissions, addresses, paired_at, last_connected, trusted FROM devices ORDER BY name COLLATE NOCASE, peer_id")?;
        let rows = statement.query_map([], row_device)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn device(&self, selector: &str) -> Result<Device> { self.resolve(selector) }

    pub fn trust(&self, device: &Device) -> Result<()> {
        validate_device(device)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        upsert_device(&tx, device)?;
        audit_tx(&tx, "device_trusted", Some(&device.peer_id), "trusted device recorded")?;
        tx.commit()?;
        Ok(())
    }

    pub fn revoke(&self, selector: &str) -> Result<()> {
        let device = self.resolve(selector)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("UPDATE devices SET trusted = 0 WHERE peer_id = ?1", [&device.peer_id])?;
        audit_tx(&tx, "device_revoked", Some(&device.peer_id), "trust revoked")?;
        tx.commit()?;
        Ok(())
    }

    pub fn rename(&self, selector: &str, name: &str) -> Result<()> {
        let device = self.resolve(selector)?;
        validate_name(name)?;
        let connection = self.connection()?;
        connection.execute("UPDATE devices SET name = ?1 WHERE peer_id = ?2", params![name.trim(), device.peer_id])?;
        Ok(())
    }

    pub fn set_permissions(&self, selector: &str, permissions: &Permissions) -> Result<()> {
        let device = self.resolve(selector)?;
        let connection = self.connection()?;
        connection.execute("UPDATE devices SET permissions = ?1 WHERE peer_id = ?2", params![serde_json::to_string(permissions)?, device.peer_id])?;
        Ok(())
    }

    pub fn touch(&self, peer: &str, addresses: &[String]) -> Result<()> {
        peer.parse::<libp2p::PeerId>().context("invalid peer id")?;
        validate_addresses(addresses)?;
        let connection = self.connection()?;
        connection.execute("UPDATE devices SET addresses = ?1, last_connected = ?2 WHERE peer_id = ?3", params![serde_json::to_string(addresses)?, now() as i64, peer])?;
        Ok(())
    }

    pub fn authorize(&self, peer: &str) -> Result<Device> {
        peer.parse::<libp2p::PeerId>().context("invalid peer id")?;
        let connection = self.connection()?;
        connection.query_row("SELECT peer_id, public_key, device_id, name, os, permissions, addresses, paired_at, last_connected, trusted FROM devices WHERE peer_id = ?1 AND trusted = 1", [peer], row_device)
            .optional()?.ok_or_else(|| anyhow!("peer is not trusted"))
    }

    pub fn create_pairing(&self, token: &PairingToken, permissions: &Permissions) -> Result<()> {
        // Validate before storing: encode performs all public token validation without logging it.
        token.encode()?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("UPDATE pairing_tokens SET active = 0 WHERE active = 1", [])?;
        tx.execute("INSERT INTO pairing_tokens(secret_hash, expires_at, permissions, active, created_at) VALUES(?1, ?2, ?3, 1, ?4)", params![token.secret_hash(), token.expires_at as i64, serde_json::to_string(permissions)?, now() as i64])?;
        audit_tx(&tx, "pairing_created", Some(&token.peer_id), "one-time pairing enabled")?;
        tx.commit()?;
        Ok(())
    }

    pub fn consume_pairing(&self, secret: &str, device: &Device) -> Result<Permissions> {
        validate_device(device)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let hash = sha256_hex(secret);
        let permissions: Option<String> = tx.query_row("SELECT permissions FROM pairing_tokens WHERE secret_hash = ?1 AND active = 1 AND expires_at > ?2", params![hash, now() as i64], |row| row.get(0)).optional()?;
        let permissions = permissions.ok_or_else(|| anyhow!("pairing secret is invalid, expired, or already used"))?;
        let changed = tx.execute("UPDATE pairing_tokens SET active = 0 WHERE secret_hash = ?1 AND active = 1", [hash])?;
        if changed != 1 { bail!("pairing secret was already consumed"); }
        let permissions: Permissions = serde_json::from_str(&permissions).context("stored pairing permission is invalid")?;
        let mut trusted = device.clone(); trusted.permissions = permissions.clone(); trusted.trusted = true;
        upsert_device(&tx, &trusted)?;
        audit_tx(&tx, "pairing_consumed", Some(&device.peer_id), "device enrolled")?;
        tx.commit()?;
        Ok(permissions)
    }

    pub fn cancel_pairing(&self) -> Result<()> {
        let connection = self.connection()?;
        connection.execute("UPDATE pairing_tokens SET active = 0 WHERE active = 1", [])?;
        Ok(())
    }

    pub fn claim_request(&self, peer: &str, request_id: Uuid) -> Result<()> {
        peer.parse::<libp2p::PeerId>().context("invalid peer id")?;
        let connection = self.connection()?;
        match connection.execute("INSERT INTO requests(peer_id, request_id, created_at) VALUES(?1, ?2, ?3)", params![peer, request_id.to_string(), now() as i64]) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::ConstraintViolation => bail!("replayed request rejected"),
            Err(error) => Err(error.into()),
        }
    }

    pub fn audit(&self, event: &str, peer: Option<&str>, detail: &str) -> Result<()> {
        validate_event(event)?;
        if let Some(peer) = peer { peer.parse::<libp2p::PeerId>().context("invalid audit peer")?; }
        let connection = self.connection()?;
        connection.execute("INSERT INTO audit_log(event, peer_id, detail, created_at) VALUES(?1, ?2, ?3, ?4)", params![event, peer, safe_detail(detail), now() as i64])?;
        Ok(())
    }

    pub fn logs(&self, limit: usize) -> Result<Vec<String>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT event, peer_id, detail, created_at FROM audit_log ORDER BY id DESC LIMIT ?1")?;
        let rows = statement.query_map([limit.min(1_000) as i64], |row| {
            let event: String = row.get(0)?; let peer: Option<String> = row.get(1)?; let detail: String = row.get(2)?; let created: i64 = row.get(3)?;
            Ok(format!("{created} {event} {} {detail}", peer.unwrap_or_else(|| "local".into())))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    fn resolve(&self, selector: &str) -> Result<Device> {
        let selector = selector.trim();
        if selector.is_empty() { bail!("device selector is empty"); }
        if let Ok(index) = selector.parse::<usize>() {
            if index == 0 { bail!("device numbers start at 1"); }
            return self.devices()?.into_iter().nth(index - 1).ok_or_else(|| anyhow!("device number not found"));
        }
        let connection = self.connection()?;
        let exact_peer = connection.query_row("SELECT peer_id, public_key, device_id, name, os, permissions, addresses, paired_at, last_connected, trusted FROM devices WHERE peer_id = ?1", [selector], row_device).optional()?;
        if let Some(device) = exact_peer { return Ok(device); }
        let mut statement = connection.prepare("SELECT peer_id, public_key, device_id, name, os, permissions, addresses, paired_at, last_connected, trusted FROM devices WHERE name = ?1 COLLATE NOCASE")?;
        let matches = statement.query_map([selector], row_device)?.collect::<rusqlite::Result<Vec<_>>>()?;
        match matches.len() { 0 => bail!("device not found"), 1 => Ok(matches.into_iter().next().unwrap()), _ => bail!("device name is ambiguous; use its peer id") }
    }

    fn connection(&self) -> Result<Connection> {
        let connection = Connection::open(&self.path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        Ok(connection)
    }

    fn migrate(&self, connection: &mut Connection) -> Result<()> {
        connection.execute_batch("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER NOT NULL);")?;
        let current: Option<i64> = connection.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| row.get(0)).optional()?.flatten();
        let current = current.unwrap_or(0);
        if current > SCHEMA_VERSION { bail!("trust database uses newer schema {current}"); }
        if current < 1 {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch("\
                CREATE TABLE devices (peer_id TEXT PRIMARY KEY NOT NULL, public_key BLOB NOT NULL, device_id TEXT NOT NULL, name TEXT NOT NULL, os TEXT NOT NULL, permissions TEXT NOT NULL, addresses TEXT NOT NULL, paired_at INTEGER NOT NULL, last_connected INTEGER, trusted INTEGER NOT NULL CHECK(trusted IN (0,1)));\
                CREATE TABLE pairing_tokens (secret_hash TEXT PRIMARY KEY NOT NULL, expires_at INTEGER NOT NULL, permissions TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)), created_at INTEGER NOT NULL);\
                CREATE TABLE requests (peer_id TEXT NOT NULL, request_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(peer_id, request_id));\
                CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, peer_id TEXT, detail TEXT NOT NULL, created_at INTEGER NOT NULL);\
            ")?;
            tx.execute("INSERT INTO schema_migrations(version) VALUES(1)", [])?;
            tx.commit()?;
        }
        Ok(())
    }
}

fn row_device(row: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    let paired_at: i64 = row.get(7)?; let last: Option<i64> = row.get(8)?; let trusted: i64 = row.get(9)?;
    Ok(Device { peer_id: row.get(0)?, public_key: row.get(1)?, device_id: row.get(2)?, name: row.get(3)?, os: row.get(4)?, permissions: serde_json::from_str(&row.get::<_, String>(5)?).map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e)))?, addresses: serde_json::from_str(&row.get::<_, String>(6)?).map_err(|e| rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e)))?, paired_at: paired_at as u64, last_connected: last.map(|value| value as u64), trusted: trusted != 0 })
}

fn upsert_device(tx: &rusqlite::Transaction<'_>, device: &Device) -> Result<()> {
    tx.execute("INSERT INTO devices(peer_id, public_key, device_id, name, os, permissions, addresses, paired_at, last_connected, trusted) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(peer_id) DO UPDATE SET public_key=excluded.public_key, device_id=excluded.device_id, name=excluded.name, os=excluded.os, permissions=excluded.permissions, addresses=excluded.addresses, last_connected=excluded.last_connected, trusted=excluded.trusted", params![device.peer_id, device.public_key, device.device_id, device.name, device.os, serde_json::to_string(&device.permissions)?, serde_json::to_string(&device.addresses)?, device.paired_at as i64, device.last_connected.map(|v| v as i64), i64::from(device.trusted)])?;
    Ok(())
}
fn audit_tx(tx: &rusqlite::Transaction<'_>, event: &str, peer: Option<&str>, detail: &str) -> Result<()> { tx.execute("INSERT INTO audit_log(event, peer_id, detail, created_at) VALUES(?1, ?2, ?3, ?4)", params![event, peer, safe_detail(detail), now() as i64])?; Ok(()) }
fn validate_name(name: &str) -> Result<()> { if name.trim().is_empty() || name.len() > 128 || name.contains('\0') { bail!("device name must be 1 to 128 printable characters"); } Ok(()) }
fn validate_addresses(addresses: &[String]) -> Result<()> { if addresses.len() > 32 { bail!("too many device addresses"); } for address in addresses { if address.len() > 512 { bail!("device address is too long"); } address.parse::<libp2p::Multiaddr>().context("invalid device multiaddress")?; } Ok(()) }
fn validate_device(device: &Device) -> Result<()> {
    let peer = device.peer_id.parse::<libp2p::PeerId>().context("invalid device peer id")?;
    if device.public_key.is_empty() || device.public_key.len() > 4096 { bail!("invalid device public key"); }
    let public = libp2p::identity::PublicKey::try_decode_protobuf(&device.public_key).context("invalid device public key encoding")?;
    if public.to_peer_id() != peer { bail!("device public key does not match peer id"); }
    Uuid::parse_str(&device.device_id).context("invalid device id")?;
    validate_name(&device.name)?;
    if device.os.len() > 128 { bail!("device OS value is too long"); }
    validate_addresses(&device.addresses)
}
fn validate_event(event: &str) -> Result<()> { if event.is_empty() || event.len() > 64 || !event.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') { bail!("invalid audit event"); } Ok(()) }
fn safe_detail(detail: &str) -> String { let lower = detail.to_ascii_lowercase(); if lower.contains("secret") || lower.contains("token") || lower.contains("password") || lower.contains("clipboard") || lower.contains("command") { "redacted sensitive detail".into() } else { detail.chars().filter(|c| !c.is_control()).take(256).collect() } }
fn sha256_hex(value: &str) -> String { use sha2::Digest; hex::encode(sha2::Sha256::digest(value.as_bytes())) }

#[cfg(test)]
mod tests {
    use super::*; use libp2p::identity; use std::{sync::Arc, thread}; use tempfile::tempdir;
    fn device() -> Device { let key = identity::Keypair::generate_ed25519(); Device { peer_id: key.public().to_peer_id().to_string(), public_key: key.public().encode_protobuf(), device_id: Uuid::new_v4().to_string(), name: "Office".into(), os: "Linux".into(), permissions: Permissions::view_only(), addresses: vec!["/ip4/127.0.0.1/tcp/44344".into()], paired_at: now(), last_connected: None, trusted: true } }
    #[test] fn revocation_rechecks_authorization_and_replay_is_durable() { let temp=tempdir().unwrap(); let store=Store::open(temp.path()).unwrap(); let d=device(); store.trust(&d).unwrap(); assert_eq!(store.authorize(&d.peer_id).unwrap().permissions, Permissions::view_only()); store.set_permissions(&d.peer_id, &Permissions::standard()).unwrap(); assert_eq!(Store::open(temp.path()).unwrap().authorize(&d.peer_id).unwrap().permissions, Permissions::standard()); let request=Uuid::new_v4(); store.claim_request(&d.peer_id,request).unwrap(); assert!(store.claim_request(&d.peer_id,request).is_err()); store.revoke(&d.peer_id).unwrap(); assert!(store.authorize(&d.peer_id).is_err()); }
    #[test] fn pairing_is_atomic_and_single_use() { let temp=tempdir().unwrap(); let store=Arc::new(Store::open(temp.path()).unwrap()); let host=identity::Keypair::generate_ed25519().public().to_peer_id().to_string(); let token=PairingToken::generate(host,vec!["/ip4/127.0.0.1/tcp/44344".into()],60).unwrap(); store.create_pairing(&token,&Permissions::standard()).unwrap(); let mut workers=Vec::new(); for _ in 0..8 { let s=store.clone(); let secret=token.secret.clone(); workers.push(thread::spawn(move || s.consume_pairing(&secret,&device()).is_ok())); } assert_eq!(workers.into_iter().map(|w| w.join().unwrap()).filter(|ok| *ok).count(),1); }
    #[test] fn newer_schema_is_rejected() { let temp=tempdir().unwrap(); let store=Store::open(temp.path()).unwrap(); let connection=Connection::open(&store.path).unwrap(); connection.execute("INSERT INTO schema_migrations(version) VALUES(99)",[]).unwrap(); assert!(Store::open(temp.path()).is_err()); }
}
