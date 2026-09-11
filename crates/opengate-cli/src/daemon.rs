use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use libp2p::{PeerId, identity::PublicKey};
use opengate_cli::traffic::{Counters, Metered};
use opengate_core::{Config, ConnectionPreferences, Device, Store};
use opengate_network::{Incoming, NetworkOptions, Node};
use opengate_protocol::*;
use opengate_security::{Identity, PairingToken, now, secure_read, secure_write};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

#[derive(Serialize, Deserialize)]
pub struct Endpoint {
    pub address: String,
    pub secret: String,
    pub pid: u32,
}

struct State {
    dir: PathBuf,
    identity: Identity,
    store: Store,
    config: RwLock<Config>,
    node: Node,
    secret: String,
    stop: CancellationToken,
    active: Mutex<HashMap<String, Vec<CancellationToken>>>,
    pairing_attempts: Mutex<HashMap<String, (u64, u32)>>,
    streams: Arc<Semaphore>,
    stream_capacity: usize,
    traffic: Mutex<HashMap<String, Arc<Counters>>>,
}

pub async fn run(dir: PathBuf, relay: bool, listen: Vec<String>) -> Result<()> {
    run_with_stop(dir, relay, listen, CancellationToken::new()).await
}

pub async fn run_with_stop(
    dir: PathBuf,
    relay: bool,
    listen: Vec<String>,
    external_stop: CancellationToken,
) -> Result<()> {
    let identity = Identity::load_or_create(&dir)?;
    let mut config = Config::load_or_create(&dir)?;
    if !listen.is_empty() {
        config.listen = listen;
    }
    let lock_path = dir.join("daemon.lock");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(lock_path)?;
    lock.try_lock_exclusive()
        .context("an OpenGate daemon is already running for this state directory")?;
    let store = Store::open(&dir)?;
    let (node, mut incoming) = Node::start(
        identity.keypair.clone(),
        NetworkOptions {
            listen: config.listen.clone(),
            relay_nodes: config.relay_nodes.clone(),
            bootstrap_nodes: config.bootstrap_nodes.clone(),
            relay_server: relay,
            max_connections: config.max_connections,
            reconnect: config.reconnect,
            relay_limits: config.relay_limits.clone(),
        },
    )
    .await?;
    for device in store.devices()? {
        if device.trusted && device.connection_preferences.auto_reconnect {
            node.add_peer(device.peer_id.parse()?, device.addresses)
                .await?;
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    let secret = hex::encode(random);
    let endpoint = Endpoint {
        address: listener.local_addr()?.to_string(),
        secret: secret.clone(),
        pid: std::process::id(),
    };
    secure_write(
        &dir.join("daemon.endpoint"),
        &serde_json::to_vec(&endpoint)?,
    )?;
    let state = Arc::new(State {
        dir: dir.clone(),
        identity,
        store,
        streams: Arc::new(Semaphore::new(config.max_streams)),
        stream_capacity: config.max_streams,
        traffic: Mutex::new(HashMap::new()),
        config: RwLock::new(config),
        node,
        secret,
        stop: CancellationToken::new(),
        active: Mutex::new(HashMap::new()),
        pairing_attempts: Mutex::new(HashMap::new()),
    });
    state.store.audit(
        "service_started",
        None,
        if relay {
            "relay enabled"
        } else {
            "user daemon"
        },
    )?;
    let local_slots = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    let signal = shutdown_signal();
    tokio::pin!(signal);
    loop {
        tokio::select! {
            _=&mut signal => break,
            _=external_stop.cancelled()=>break,
            _=state.stop.cancelled()=>break,
            Some(result)=tasks.join_next()=> {if let Err(error)=result {tracing::warn!(%error,"session task failed");}},
            connection=listener.accept()=> {
                let (stream,_)=connection?;
                if let Ok(permit)=local_slots.clone().try_acquire_owned() { let state=state.clone();tasks.spawn(async move {let _permit=permit;if let Err(error)=handle_local(state,stream).await {tracing::debug!(%error,"local request ended");}}); }
            },
            Some(incoming)=incoming.recv()=> {
                if let Ok(permit)=state.streams.clone().try_acquire_owned() {let state=state.clone();tasks.spawn(async move {let _permit=permit;if let Err(error)=handle_remote(state,incoming).await {tracing::debug!(%error,"remote stream ended");}});}
            }
        }
    }
    state.stop.cancel();
    for tokens in state.active.lock().await.values() {
        for token in tokens {
            token.cancel();
        }
    }
    state.node.shutdown().await?;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    state
        .store
        .audit("service_stopped", None, "clean shutdown")?;
    let _ = std::fs::remove_file(dir.join("daemon.endpoint"));
    drop(lock);
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_=term.recv()=>{},_=tokio::signal::ctrl_c()=>{}};
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

impl State {
    async fn status(&self) -> Result<serde_json::Value> {
        let mut network = serde_json::to_value(self.node.snapshot().await?)?;
        if let Some(connections) = network["connections"].as_array_mut() {
            for connection in connections {
                let saved = connection["peer_id"]
                    .as_str()
                    .and_then(|peer| self.store.authorize(peer).ok());
                connection["trusted"] = serde_json::json!(saved.is_some());
                connection["authenticated"] = serde_json::json!(saved.is_some());
                connection["permissions_granted_to_peer"] =
                    serde_json::to_value(saved.as_ref().map(|d| &d.permissions))?;
                connection["device_name"] = serde_json::to_value(saved.as_ref().map(|d| &d.name))?;
            }
        }
        Ok(
            serde_json::json!({"device":self.hello().await?,"network":network,
            "active_streams":self.stream_capacity-self.streams.available_permits(),"traffic":self.traffic_snapshot().await,
            "full_admin_enabled":self.config.read().await.allow_admin,"process_elevated":is_elevated()}),
        )
    }
    async fn metered<S>(&self, peer: &str, stream: S) -> Metered<S> {
        let counters = self
            .traffic
            .lock()
            .await
            .entry(peer.into())
            .or_default()
            .clone();
        Metered::new(
            stream,
            counters,
            self.config.read().await.bandwidth_limit_bytes_per_second,
        )
    }
    async fn traffic_snapshot(&self) -> Vec<serde_json::Value> {
        use std::sync::atomic::Ordering;
        self.traffic.lock().await.iter().map(|(peer,c)|serde_json::json!({"peer_id":peer,"received_bytes":c.received.load(Ordering::Relaxed),"sent_bytes":c.sent.load(Ordering::Relaxed),"active_streams":c.active.load(Ordering::Relaxed)})).collect()
    }
    async fn hello(&self) -> Result<PeerHello> {
        let snapshot = self.node.snapshot().await?;
        Ok(PeerHello {
            app_version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: opengate_protocol::VERSION,
            peer_id: self.identity.peer_id().to_string(),
            public_key: self.identity.keypair.public().encode_protobuf(),
            device_id: self.identity.device_id.to_string(),
            name: self.config.read().await.name.clone(),
            os: std::env::consts::OS.into(),
            addresses: snapshot.listeners,
        })
    }
    async fn cancel_peer(&self, peer: &str) {
        if let Some(tokens) = self.active.lock().await.remove(peer) {
            for token in tokens {
                token.cancel();
            }
        }
    }
}

fn checked_device(peer: PeerId, hello: PeerHello, permissions: Permissions) -> Result<Device> {
    ensure!(
        hello.app_version.len() <= 64 && !hello.app_version.chars().any(char::is_control),
        "invalid application version"
    );
    ensure!(
        hello.protocol_version == opengate_protocol::VERSION,
        "incompatible OpenGate version: local {} (protocol {}), remote {} (protocol {}); upgrade required",
        env!("CARGO_PKG_VERSION"),
        opengate_protocol::VERSION,
        hello.app_version,
        hello.protocol_version
    );
    ensure!(
        hello.peer_id == peer.to_string(),
        "peer identity does not match encrypted transport"
    );
    let public = PublicKey::try_decode_protobuf(&hello.public_key)?;
    ensure!(
        public.to_peer_id() == peer,
        "public key does not match authenticated peer"
    );
    ensure!(
        hello.name.len() <= 128 && !hello.name.chars().any(char::is_control),
        "invalid device name"
    );
    ensure!(
        hello.os.len() <= 64 && hello.addresses.len() <= 32,
        "invalid device metadata"
    );
    uuid::Uuid::parse_str(&hello.device_id)?;
    for addr in &hello.addresses {
        let addr: libp2p::Multiaddr = addr.parse()?;
        if let Some(libp2p::multiaddr::Protocol::P2p(id)) = addr.iter().last() {
            ensure!(id == peer, "address peer identity mismatch");
        }
    }
    Ok(Device {
        peer_id: peer.to_string(),
        public_key: hello.public_key,
        device_id: hello.device_id,
        name: hello.name,
        os: hello.os,
        permissions,
        addresses: hello.addresses,
        connection_preferences: ConnectionPreferences::default(),
        paired_at: now(),
        last_connected: Some(now()),
        trusted: true,
    })
}

async fn open_remote(
    state: &State,
    device: &Device,
    request: RemoteRequest,
) -> Result<(Metered<opengate_network::PeerStream>, Reply)> {
    state.store.authorize(&device.peer_id)?;
    device.connection_preferences.validate()?;
    let mut stream = tokio::time::timeout(
        Duration::from_secs(device.connection_preferences.connection_timeout_seconds),
        state.node.open(
            device.peer_id.parse()?,
            request.protocol(),
            &device.addresses,
        ),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "saved device connection timeout reached",
        )
    })?
    .map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::ConnectionAborted, error.to_string())
    })?;
    let open = OpenRequest {
        request_id: uuid::Uuid::new_v4(),
        request,
    };
    write_frame_with_id(&mut stream, open.request_id, &open).await?;
    let reply: Reply =
        tokio::time::timeout(Duration::from_secs(30), read_frame(&mut stream)).await??;
    reply.check()?;
    Ok((state.metered(&device.peer_id, stream).await, reply))
}

async fn handle_remote(state: Arc<State>, mut incoming: Incoming) -> Result<()> {
    let open: OpenRequest =
        tokio::time::timeout(Duration::from_secs(15), read_frame(&mut incoming.stream)).await??;
    let id = open.request_id;
    let result = authorize_open(&state, incoming.peer, &incoming.protocol, &open).await;
    let (data, cancel) = match result {
        Ok(value) => value,
        Err(error) => {
            let category = match &open.request {
                RemoteRequest::Pair { .. } => ErrorCode::Pairing,
                RemoteRequest::Authenticate { .. } => ErrorCode::Authentication,
                _ => ErrorCode::Authorization,
            };
            let error = domain_error(error, category);
            state.store.audit(
                "authentication_or_permission_rejected",
                Some(&incoming.peer.to_string()),
                "request rejected",
            )?;
            write_frame_with_id(&mut incoming.stream, id, &Reply::from_error(&error)).await?;
            return Ok(());
        }
    };
    let _cancel_guard = cancel.clone().drop_guard();
    let file_root = state.config.read().await.file_root.clone();
    let allow_network_targets = state.config.read().await.allow_network_targets;
    let prepared = if let RemoteRequest::Tunnel { target, .. } = &open.request {
        match opengate_tunnel::connect_target(target, allow_network_targets, cancel.clone()).await {
            Ok(tcp) => Some(tcp),
            Err(error) => {
                write_frame_with_id(&mut incoming.stream, id, &Reply::from_error(&error)).await?;
                return Ok(());
            }
        }
    } else {
        None
    };
    write_frame_with_id(&mut incoming.stream, id, &Reply::success(data)?).await?;
    let token = cancel.clone();
    let metered = state
        .metered(&incoming.peer.to_string(), incoming.stream)
        .await;
    let future = async {
        match open.request {
            RemoteRequest::Shell(request) => {
                opengate_terminal::serve(metered, request, cancel.clone()).await
            }
            RemoteRequest::Files => {
                opengate_files::serve(
                    metered,
                    file_root,
                    incoming.peer.to_string(),
                    cancel.clone(),
                )
                .await
            }
            RemoteRequest::Tunnel { .. } => {
                opengate_tunnel::bridge(
                    metered,
                    prepared.context("tunnel socket was not prepared")?,
                    cancel.clone(),
                )
                .await
            }
            RemoteRequest::Pair { .. } | RemoteRequest::Authenticate { .. } => Ok(()),
            RemoteRequest::ClipboardGet | RemoteRequest::ClipboardSet { .. } => Ok(()),
        }
    };
    let result = tokio::select! {result=future=>result,_=token.cancelled()=>Ok(()),_=state.stop.cancelled()=>Ok(())};
    token.cancel();
    if let Some(tokens) = state
        .active
        .lock()
        .await
        .get_mut(&incoming.peer.to_string())
    {
        tokens.retain(|t| !t.is_cancelled());
    }
    result
}

async fn authorize_open(
    state: &State,
    peer: PeerId,
    protocol: &str,
    open: &OpenRequest,
) -> Result<(serde_json::Value, CancellationToken)> {
    ensure!(
        open.request.protocol() == protocol,
        "operation does not match negotiated protocol"
    );
    let peer_text = peer.to_string();
    if let RemoteRequest::Pair { secret, hello } = &open.request {
        ensure!(
            state.config.read().await.allow_pairing,
            "pairing is disabled by the owner"
        );
        {
            let mut attempts = state.pairing_attempts.lock().await;
            attempts.retain(|_, (at, _)| now().saturating_sub(*at) < 60);
            ensure!(
                attempts.len() < 1024 || attempts.contains_key(&peer_text),
                "pairing rate limit reached"
            );
            let entry = attempts.entry(peer_text.clone()).or_insert((now(), 0));
            entry.1 += 1;
            ensure!(
                entry.1 <= 5,
                "too many pairing attempts; retry after one minute"
            );
        }
        let device = checked_device(peer, hello.clone(), Permissions::view_only())?;
        let permissions = state.store.consume_pairing(secret, &device)?;
        state.node.add_peer(peer, device.addresses).await?;
        state.store.audit(
            "device_paired",
            Some(&peer_text),
            "one-time pairing accepted",
        )?;
        return Ok((
            serde_json::json!({"device":state.hello().await?,"permissions":permissions}),
            CancellationToken::new(),
        ));
    }
    let device = state.store.authorize(&peer_text)?;
    ensure!(
        PublicKey::try_decode_protobuf(&device.public_key)?.to_peer_id() == peer,
        "stored public identity mismatch"
    );
    if let RemoteRequest::Authenticate { hello } = &open.request {
        let current = checked_device(peer, hello.clone(), device.permissions.clone())?;
        state.store.touch(&peer_text, &current.addresses)?;
        if device.connection_preferences.auto_reconnect {
            state.node.add_peer(peer, current.addresses).await?;
        }
        state.store.audit(
            "connection_authenticated",
            Some(&peer_text),
            "saved device public key",
        )?;
        return Ok((
            serde_json::json!({"device":state.hello().await?,"permissions":device.permissions}),
            CancellationToken::new(),
        ));
    }
    check_permissions(
        &device.permissions,
        &open.request,
        &*state.config.read().await,
    )?;
    // Register before rechecking trust; this closes the revoke/open race.
    let cancel = state.stop.child_token();
    let registration_guard = cancel.clone().drop_guard();
    {
        let mut active = state.active.lock().await;
        let tokens = active.entry(peer_text.clone()).or_default();
        tokens.retain(|t| !t.is_cancelled());
        tokens.push(cancel.clone());
    }
    let current = state.store.authorize(&peer_text)?;
    check_permissions(
        &current.permissions,
        &open.request,
        &*state.config.read().await,
    )?;
    if let RemoteRequest::Shell(_) = &open.request {
        state.store.claim_request(&peer_text, open.request_id)?;
    }
    let event = match &open.request {
        RemoteRequest::Shell(_) => "terminal_opened",
        RemoteRequest::Files => "file_access",
        RemoteRequest::Tunnel { .. } => "tunnel_created",
        _ => "clipboard_access",
    };
    state
        .store
        .audit(event, Some(&peer_text), "authorized stream")?;
    let data = match &open.request {
        RemoteRequest::ClipboardGet => {
            serde_json::json!({"text":tokio::select!{value=crate::clipboard::get()=>value?,_=cancel.cancelled()=>bail!("clipboard permission revoked")}})
        }
        RemoteRequest::ClipboardSet { text } => {
            tokio::select! {value=crate::clipboard::set(text)=>value?,_=cancel.cancelled()=>bail!("clipboard permission revoked")};
            serde_json::json!({"copied":true})
        }
        _ => serde_json::json!({"authenticated":true,"encrypted":true}),
    };
    let _ = registration_guard.disarm();
    Ok((data, cancel))
}

fn check_permissions(
    permissions: &Permissions,
    request: &RemoteRequest,
    config: &Config,
) -> Result<()> {
    let permitted = match request {
        RemoteRequest::Shell(_) => permissions.terminal,
        RemoteRequest::Files => permissions.files,
        RemoteRequest::Tunnel { desktop: true, .. } => permissions.desktop,
        RemoteRequest::Tunnel { .. } => permissions.tcp_forward,
        RemoteRequest::ClipboardGet | RemoteRequest::ClipboardSet { .. } => permissions.clipboard,
        _ => false,
    };
    ensure!(permitted, "permission denied by device owner");
    if is_elevated() {
        ensure!(
            config.allow_admin && permissions.full_admin,
            "privileged daemon requires both owner-enabled admin mode and Full Admin permission"
        );
    }
    Ok(())
}

pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no arguments or memory-safety preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        opengate_service::is_elevated()
    }
}

async fn handle_local(state: Arc<State>, mut stream: TcpStream) -> Result<()> {
    let local: LocalRequest =
        tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream)).await??;
    ensure!(
        bool::from(local.auth.as_bytes().ct_eq(state.secret.as_bytes())),
        "local authentication failed"
    );
    if let LocalCommand::Open { device, request } = local.command {
        let result = async {
            let device = state.store.device(&device)?;
            open_remote(&state, &device, request).await
        }
        .await;
        match result {
            Ok((mut remote, reply)) => {
                let cancel = state.stop.child_token();
                let _cancel_guard = cancel.clone().drop_guard();
                // The local owner's revocation must also terminate outgoing streams.
                {
                    let mut active = state.active.lock().await;
                    let tokens = active
                        .entry(state.store.device(&device)?.peer_id)
                        .or_default();
                    tokens.retain(|t| !t.is_cancelled());
                    tokens.push(cancel.clone());
                }
                state
                    .store
                    .authorize(&state.store.device(&device)?.peer_id)?;
                write_frame(&mut stream, &reply).await?;
                tokio::select! {result=tokio::io::copy_bidirectional(&mut stream,&mut remote)=>{result?;},_=cancel.cancelled()=>{}}
                cancel.cancel();
            }
            Err(error) => write_frame(&mut stream, &Reply::from_error(&error)).await?,
        }
        return Ok(());
    }
    let reply = match execute_local(&state, local.command).await {
        Ok(value) => Reply::success(value)?,
        Err(error) => Reply::from_error(&error),
    };
    write_frame(&mut stream, &reply).await?;
    Ok(())
}

fn domain_error(error: anyhow::Error, code: ErrorCode) -> anyhow::Error {
    let (classified, retryable) = classify_error(&error);
    let code = if classified == ErrorCode::RateLimited {
        classified
    } else {
        code
    };
    anyhow::Error::new(OpenGateError::new(code, error.to_string(), retryable))
}

async fn execute_local(state: &State, command: LocalCommand) -> Result<serde_json::Value> {
    match command {
        LocalCommand::Status => state.status().await,
        LocalCommand::Devices => Ok(serde_json::to_value(state.store.devices()?)?),
        LocalCommand::Allow { permissions, ttl } => {
            let config = state.config.read().await;
            ensure!(config.allow_pairing, "pairing is disabled");
            ensure!(
                !permissions.full_admin || config.allow_admin,
                "enable allow_admin explicitly before granting Full Admin Access"
            );
            ensure!(
                (60..=900).contains(&ttl),
                "token lifetime must be 60 to 900 seconds"
            );
            drop(config);
            let hello = state.hello().await?;
            ensure!(
                !hello.addresses.is_empty(),
                "network listeners are starting; retry in a moment"
            );
            let token =
                PairingToken::generate(hello.peer_id.clone(), hello.addresses.clone(), ttl)?;
            state.store.create_pairing(&token, &permissions)?;
            Ok(
                serde_json::json!({"device":hello,"token":token.encode()?,"expires_at":token.expires_at,"permissions":permissions}),
            )
        }
        LocalCommand::CancelPairing => {
            state.store.cancel_pairing()?;
            Ok(serde_json::json!({"cancelled":true}))
        }
        LocalCommand::Pair { token, grant } => {
            ensure!(
                !grant.full_admin || state.config.read().await.allow_admin,
                "enable local allow_admin before granting Full Admin Access"
            );
            let token = PairingToken::decode(&token)?;
            let peer: PeerId = token.peer_id.parse()?;
            ensure!(
                peer != state.identity.peer_id(),
                "cannot pair this device with itself"
            );
            let mut remote = state.node.open_pairing(peer, &token.addresses).await?;
            let request = OpenRequest {
                request_id: uuid::Uuid::new_v4(),
                request: RemoteRequest::Pair {
                    secret: token.secret.clone(),
                    hello: state.hello().await?,
                },
            };
            write_frame_with_id(&mut remote, request.request_id, &request).await?;
            let reply: Reply =
                tokio::time::timeout(Duration::from_secs(30), read_frame(&mut remote)).await??;
            reply.check()?;
            let hello: PeerHello = serde_json::from_value(reply.data["device"].clone())?;
            let mut device = checked_device(peer, hello, grant)?;
            if device.addresses.is_empty() {
                device.addresses = token.addresses;
            }
            state.store.trust(&device)?;
            state.node.add_peer(peer, device.addresses.clone()).await?;
            state.store.audit(
                "device_paired",
                Some(&device.peer_id),
                "remote host pinned from pairing token",
            )?;
            Ok(serde_json::json!({"device":device,"remote_permissions":reply.data["permissions"]}))
        }
        LocalCommand::Connect { device } => {
            let saved = state.store.device(&device)?;
            let (_, reply) = open_remote(
                state,
                &saved,
                RemoteRequest::Authenticate {
                    hello: state.hello().await?,
                },
            )
            .await?;
            let hello: PeerHello = serde_json::from_value(reply.data["device"].clone())?;
            let current = checked_device(saved.peer_id.parse()?, hello, saved.permissions)?;
            state.store.touch(&current.peer_id, &current.addresses)?;
            Ok(reply.data)
        }
        LocalCommand::Rename { device, name } => {
            state.store.rename(&device, &name)?;
            Ok(serde_json::json!({"renamed":true}))
        }
        LocalCommand::ConnectionPreferences {
            device,
            auto_reconnect,
            connection_timeout_seconds,
        } => {
            let saved = state.store.device(&device)?;
            let mut preferences = saved.connection_preferences;
            if auto_reconnect.is_none() && connection_timeout_seconds.is_none() {
                return Ok(serde_json::to_value(preferences)?);
            }
            if let Some(enabled) = auto_reconnect {
                preferences.auto_reconnect = enabled;
            }
            if let Some(seconds) = connection_timeout_seconds {
                preferences.connection_timeout_seconds = seconds;
            }
            state
                .store
                .set_connection_preferences(&device, &preferences)?;
            if preferences.auto_reconnect && saved.trusted {
                state
                    .node
                    .add_peer(saved.peer_id.parse()?, saved.addresses)
                    .await?;
            } else {
                state.node.untrack(saved.peer_id.parse()?).await?;
            }
            Ok(serde_json::to_value(preferences)?)
        }
        LocalCommand::Revoke { device } => {
            let saved = state.store.device(&device)?;
            state.store.revoke(&device)?;
            state.cancel_peer(&saved.peer_id).await;
            state.node.disconnect(saved.peer_id.parse()?).await?;
            state.store.audit(
                "device_revoked",
                Some(&saved.peer_id),
                "trust removed and streams cancelled",
            )?;
            Ok(serde_json::json!({"revoked":true}))
        }
        LocalCommand::Permissions {
            device,
            permissions,
        } => {
            ensure!(
                !permissions.full_admin || state.config.read().await.allow_admin,
                "enable allow_admin explicitly before granting Full Admin Access"
            );
            let saved = state.store.device(&device)?;
            state.store.set_permissions(&device, &permissions)?;
            state.cancel_peer(&saved.peer_id).await;
            state.store.audit(
                "permission_changed",
                Some(&saved.peer_id),
                "active streams cancelled",
            )?;
            Ok(serde_json::to_value(permissions)?)
        }
        LocalCommand::Logs { limit } => {
            Ok(serde_json::to_value(state.store.logs(limit.min(1000))?)?)
        }
        LocalCommand::ConfigGet => Ok(serde_json::to_value(&*state.config.read().await)?),
        LocalCommand::ConfigSet { key, value } => {
            let mut guard = state.config.write().await;
            let mut config = guard.clone();
            match key.as_str() {
                "name" => {
                    ensure!(
                        !value.is_empty()
                            && value.len() <= 128
                            && !value.chars().any(char::is_control),
                        "invalid name"
                    );
                    config.name = value;
                }
                "allow_admin" => config.allow_admin = value.parse()?,
                "allow_pairing" => config.allow_pairing = value.parse()?,
                "allow_network_targets" => config.allow_network_targets = value.parse()?,
                "reconnect" => config.reconnect = value.parse()?,
                "relay_limits" => config.relay_limits = serde_json::from_str(&value)?,
                "bandwidth_limit_bytes_per_second" => {
                    config.bandwidth_limit_bytes_per_second = value.parse()?
                }
                "max_connections" => config.max_connections = value.parse()?,
                "max_streams" => config.max_streams = value.parse()?,
                "file_root" => {
                    let path = PathBuf::from(value);
                    ensure!(
                        path.is_absolute() && path.is_dir(),
                        "file_root must be an existing absolute directory"
                    );
                    config.file_root = path;
                }
                "relay_nodes" => config.relay_nodes = serde_json::from_str(&value)?,
                "bootstrap_nodes" => config.bootstrap_nodes = serde_json::from_str(&value)?,
                "listen" => {
                    config.listen = serde_json::from_str(&value)?;
                    for addr in &config.listen {
                        let _: libp2p::Multiaddr = addr.parse()?;
                    }
                }
                _ => bail!("unsupported config key"),
            }
            config.save(&state.dir)?;
            *guard = config;
            // Security policy changes invalidate existing streams; a nickname or
            // future network setting does not interrupt a running terminal/transfer.
            if matches!(
                key.as_str(),
                "allow_admin" | "allow_network_targets" | "file_root"
            ) {
                for tokens in state.active.lock().await.values() {
                    for token in tokens {
                        token.cancel();
                    }
                }
            }
            Ok(
                serde_json::json!({"saved":true,"restart_required":matches!(key.as_str(),"relay_nodes"|"bootstrap_nodes"|"listen"|"reconnect"|"relay_limits"|"max_connections"|"max_streams")}),
            )
        }
        LocalCommand::Shutdown => {
            state.stop.cancel();
            Ok(serde_json::json!({"stopping":true}))
        }
        LocalCommand::Open { .. } => bail!("stream command dispatch error"),
    }
}

pub fn endpoint(dir: &Path) -> Result<Endpoint> {
    Ok(serde_json::from_slice(&secure_read(
        &dir.join("daemon.endpoint"),
    )?)?)
}
