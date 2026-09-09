//! The authenticated transport layer used by OpenGate.
//!
//! A successful libp2p connection proves the remote [`PeerId`], but deliberately does
//! not grant application permissions. Callers must consult the trust store for every
//! returned stream. Discovery addresses are only dial candidates: explicit addresses are
//! pinned to the expected peer id before use.
//!
//! QUIC is preferred, with TCP/Noise/Yamux and DNS as fallbacks. Relay v2 and DCUtR are
//! enabled for self-hosted relays. Relay servers use bounded reservations (64), circuits
//! (16), circuit duration (120 seconds), circuit bytes (128 KiB), and libp2p's per-peer
//! and per-IP rate limiters. These intentionally conservative defaults prevent a relay
//! from becoming an unbounded traffic service; long-running application transfers should
//! use direct connections after DCUtR has upgraded them.

use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use futures::StreamExt;
use libp2p::{
    autonat, dcutr, identify, identity, mdns, noise, ping, relay,
    swarm::{
        behaviour::toggle::Toggle,
        dial_opts::{DialOpts, PeerCondition},
        NetworkBehaviour, StreamProtocol, SwarmEvent,
    },
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{mpsc, oneshot, RwLock},
    time::{interval, timeout, MissedTickBehavior},
};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

/// The Tokio-compatible form of a libp2p negotiated substream.
pub type PeerStream = Compat<libp2p::swarm::Stream>;

pub const CONTROL_PROTOCOL: &str = "/opengate/control/1";
pub const TERMINAL_PROTOCOL: &str = "/opengate/terminal/1";
pub const FILES_PROTOCOL: &str = "/opengate/files/1";
pub const TCP_FORWARD_PROTOCOL: &str = "/opengate/tcp-forward/1";
pub const DESKTOP_PROTOCOL: &str = "/opengate/desktop/1";
pub const HEARTBEAT_PROTOCOL: &str = "/opengate/heartbeat/1";
pub const CLIPBOARD_PROTOCOL: &str = "/opengate/clipboard/1";

const PROTOCOLS: &[&str] = &[
    CONTROL_PROTOCOL,
    TERMINAL_PROTOCOL,
    FILES_PROTOCOL,
    TCP_FORWARD_PROTOCOL,
    DESKTOP_PROTOCOL,
    HEARTBEAT_PROTOCOL,
    CLIPBOARD_PROTOCOL,
];
const RETRY_STEPS: &[u64] = &[1, 2, 4, 8, 15, 30, 60];
const STABLE_CONNECTION: Duration = Duration::from_secs(30);
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const INCOMING_QUEUE: usize = 64;

/// A negotiated, authenticated inbound stream. Authorization is intentionally left to the
/// application trust layer; transport authentication alone is insufficient.
pub struct Incoming {
    pub peer: PeerId,
    pub protocol: String,
    pub stream: PeerStream,
}

/// Runtime network configuration. Relay and bootstrap entries are normal libp2p multiaddrs;
/// when supplied they must end in the relay/bootstrap peer id or they are rejected.
#[derive(Debug, Clone)]
pub struct NetworkOptions {
    pub listen: Vec<String>,
    pub relay_nodes: Vec<String>,
    pub bootstrap_nodes: Vec<String>,
    pub relay_server: bool,
    pub max_connections: u32,
    pub reconnect: bool,
}

impl Default for NetworkOptions {
    fn default() -> Self {
        Self {
            listen: Vec::new(),
            relay_nodes: Vec::new(),
            bootstrap_nodes: Vec::new(),
            relay_server: false,
            max_connections: 64,
            reconnect: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub peer_id: String,
    pub listeners: Vec<String>,
    pub connections: Vec<ConnectionInfo>,
    pub discovered: Vec<DiscoveredPeer>,
    pub nat_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub peer_id: String,
    pub address: String,
    /// Evidence from the established libp2p endpoint: LAN, IPv6 DIRECT, DIRECT,
    /// HOLE-PUNCHED (a direct connection following a relayed one), or RELAYED.
    pub path: String,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    pub peer_id: String,
    pub addresses: Vec<String>,
}

#[derive(Clone)]
pub struct Node {
    commands: mpsc::Sender<Command>,
    state: Arc<RwLock<SharedState>>,
}

impl Node {
    /// Start a Tokio swarm and return the application-facing inbound stream receiver.
    pub async fn start(
        key: identity::Keypair,
        options: NetworkOptions,
    ) -> Result<(Node, mpsc::Receiver<Incoming>)> {
        let peer_id = key.public().to_peer_id();
        let max_connections = options.max_connections.max(1) as usize;
        let relay_config = options.relay_server.then(relay_limits);

        let mut swarm = SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
            .context("configure TCP Noise/Yamux transport")?
            .with_quic()
            .with_dns()
            .context("configure DNS transport")?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .context("configure relay client transport")?
            .with_behaviour(move |key, relay_client| -> std::result::Result<Behaviour, Box<dyn std::error::Error + Send + Sync>> {
                let local_peer = key.public().to_peer_id();
                let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer)?;
                Ok(Behaviour {
                    stream: libp2p_stream::Behaviour::new(),
                    identify: identify::Behaviour::new(identify::Config::new_with_signed_peer_record(
                        "/opengate/1".to_owned(),
                        key,
                    )),
                    ping: ping::Behaviour::new(
                        ping::Config::new()
                            .with_interval(Duration::from_secs(10))
                            .with_timeout(Duration::from_secs(30)),
                    ),
                    mdns: Toggle::from(Some(mdns)),
                    autonat: autonat::Behaviour::new(local_peer, autonat::Config::default()),
                    relay_client,
                    relay_server: Toggle::from(relay_config.map(|cfg| {
                        relay::Behaviour::new(local_peer, cfg)
                    })),
                    dcutr: dcutr::Behaviour::new(local_peer),
                })
            })
            .context("configure OpenGate network behaviours")?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(90))
                    .with_max_negotiating_inbound_streams(32)
            })
            .build();

        let mut control = swarm.behaviour().stream.new_control();
        let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_QUEUE);
        for protocol in PROTOCOLS {
            let incoming = control
                .accept(StreamProtocol::new(protocol))
                .map_err(|e| anyhow!("register {protocol}: {e}"))?;
            spawn_incoming_forwarder(incoming, incoming_tx.clone(), protocol);
        }
        drop(incoming_tx);

        let listeners = if options.listen.is_empty() {
            vec![
                "/ip4/0.0.0.0/udp/0/quic-v1".to_owned(),
                "/ip4/0.0.0.0/tcp/0".to_owned(),
            ]
        } else {
            options.listen.clone()
        };
        for address in listeners {
            swarm
                .listen_on(address.parse().with_context(|| format!("invalid listen address {address}"))?)
                .with_context(|| format!("listen on {address}"))?;
        }

        let state = Arc::new(RwLock::new(SharedState::new(peer_id)));
        let (command_tx, command_rx) = mpsc::channel(128);
        let node = Node {
            commands: command_tx,
            state: state.clone(),
        };
        tokio::spawn(run_swarm(
            swarm,
            control,
            command_rx,
            state,
            max_connections,
            options.reconnect,
            options.relay_nodes,
            options.bootstrap_nodes,
        ));
        Ok((node, incoming_rx))
    }

    pub async fn open(
        &self,
        peer: PeerId,
        protocol: &str,
        addresses: &[String],
    ) -> Result<PeerStream> {
        ensure_protocol(protocol)?;
        let addresses = pinned_addresses(peer, addresses)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Open {
                peer,
                protocol: protocol.to_owned(),
                addresses,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("network node has stopped"))?;
        reply_rx.await.map_err(|_| anyhow!("network node stopped opening stream"))?
    }

    pub async fn add_peer(&self, peer: PeerId, addresses: Vec<String>) -> Result<()> {
        let addresses = pinned_addresses(peer, &addresses)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::AddPeer { peer, addresses, reply: reply_tx })
            .await
            .map_err(|_| anyhow!("network node has stopped"))?;
        reply_rx.await.map_err(|_| anyhow!("network node stopped adding peer"))?
    }

    pub async fn disconnect(&self, peer: PeerId) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Disconnect { peer, reply: reply_tx })
            .await
            .map_err(|_| anyhow!("network node has stopped"))?;
        reply_rx.await.map_err(|_| anyhow!("network node stopped disconnecting peer"))?
    }

    pub async fn snapshot(&self) -> Result<Snapshot> {
        let state = self.state.read().await;
        Ok(state.snapshot())
    }

    pub async fn shutdown(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Shutdown { reply: reply_tx })
            .await
            .map_err(|_| anyhow!("network node has already stopped"))?;
        reply_rx.await.map_err(|_| anyhow!("network node stopped during shutdown"))
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    stream: libp2p_stream::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    mdns: Toggle<mdns::tokio::Behaviour>,
    autonat: autonat::Behaviour,
    relay_client: relay::client::Behaviour,
    relay_server: Toggle<relay::Behaviour>,
    dcutr: dcutr::Behaviour,
}

enum Command {
    Open {
        peer: PeerId,
        protocol: String,
        addresses: Vec<Multiaddr>,
        reply: oneshot::Sender<Result<PeerStream>>,
    },
    AddPeer { peer: PeerId, addresses: Vec<Multiaddr>, reply: oneshot::Sender<Result<()>> },
    Disconnect { peer: PeerId, reply: oneshot::Sender<Result<()>> },
    Shutdown { reply: oneshot::Sender<()> },
}

#[derive(Default)]
struct SharedState {
    peer_id: String,
    listeners: HashSet<String>,
    connections: HashMap<PeerId, ConnectionInfo>,
    discovered: HashMap<PeerId, HashSet<String>>,
    nat_status: String,
    hole_punched: HashSet<PeerId>,
}

impl SharedState {
    fn new(peer_id: PeerId) -> Self {
        Self { peer_id: peer_id.to_string(), nat_status: "UNKNOWN".to_owned(), ..Self::default() }
    }

    fn snapshot(&self) -> Snapshot {
        let mut listeners: Vec<_> = self.listeners.iter().cloned().collect();
        listeners.sort();
        let mut connections: Vec<_> = self.connections.values().cloned().collect();
        connections.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        let mut discovered: Vec<_> = self.discovered.iter().map(|(peer, addresses)| {
            let mut addresses: Vec<_> = addresses.iter().cloned().collect();
            addresses.sort();
            DiscoveredPeer { peer_id: peer.to_string(), addresses }
        }).collect();
        discovered.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        Snapshot { peer_id: self.peer_id.clone(), listeners, connections, discovered, nat_status: self.nat_status.clone() }
    }
}

struct TrackedPeer {
    addresses: Vec<Multiaddr>,
    attempt: usize,
    next_retry: Instant,
    connected_at: Option<Instant>,
    direct_attempted: bool,
}

async fn run_swarm(
    mut swarm: libp2p::Swarm<Behaviour>,
    control: libp2p_stream::Control,
    mut commands: mpsc::Receiver<Command>,
    state: Arc<RwLock<SharedState>>,
    max_connections: usize,
    reconnect: bool,
    relay_nodes: Vec<String>,
    bootstrap_nodes: Vec<String>,
) {
    let mut peers: HashMap<PeerId, TrackedPeer> = HashMap::new();
    let mut revoked = HashSet::new();
    let mut tick = interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    for address in relay_nodes {
        if let Err(error) = configure_relay_node(&mut swarm, &address) {
            tracing::warn!(%address, %error, "ignoring invalid configured relay node");
        }
    }
    for address in bootstrap_nodes {
        if let Err(error) = dial_configured_node(&mut swarm, &address) {
            tracing::warn!(%address, %error, "ignoring invalid configured network node");
        }
    }

    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Open { peer, protocol, addresses, reply }) => {
                    if revoked.contains(&peer) {
                        let _ = reply.send(Err(anyhow!("peer {peer} is disconnected; call add_peer before reconnecting")));
                        continue;
                    }
                    let tracked = peers.contains_key(&peer);
                    if tracked {
                        if !addresses.is_empty() {
                            track_addresses(&mut peers, peer, addresses);
                        }
                        if !swarm.is_connected(&peer) {
                            dial_tracked(&mut swarm, peer, &mut peers);
                        }
                    } else if !swarm.is_connected(&peer) && !addresses.is_empty() {
                        dial_once(&mut swarm, peer, addresses);
                    }
                    let mut control = control.clone();
                    tokio::spawn(async move {
                        let result = match protocol_stream(&protocol) {
                            Ok(protocol) => match timeout(OPEN_TIMEOUT, control.open_stream(peer, protocol)).await {
                                Ok(result) => result
                                    .map_err(|e| anyhow!("open stream to {peer}: {e}"))
                                    .map(FuturesAsyncReadCompatExt::compat),
                                Err(_) => Err(anyhow!("timed out opening stream to {peer}")),
                            },
                            Err(error) => Err(error),
                        };
                        let _ = reply.send(result);
                    });
                }
                Some(Command::AddPeer { peer, addresses, reply }) => {
                    revoked.remove(&peer);
                    track_addresses(&mut peers, peer, addresses);
                    dial_tracked(&mut swarm, peer, &mut peers);
                    let _ = reply.send(Ok(()));
                }
                Some(Command::Disconnect { peer, reply }) => {
                    // Revocation/removal is represented by forgetting the tracked peer. A later
                    // ConnectionClosed event therefore cannot schedule it again.
                    peers.remove(&peer);
                    revoked.insert(peer);
                    let _ = swarm.disconnect_peer_id(peer);
                    let _ = reply.send(Ok(()));
                }
                Some(Command::Shutdown { reply }) => {
                    for peer in swarm.connected_peers().copied().collect::<Vec<_>>() {
                        let _ = swarm.disconnect_peer_id(peer);
                    }
                    let _ = reply.send(());
                    break;
                }
                None => break,
            },
            _ = tick.tick(), if reconnect => {
                let now = Instant::now();
                let mut retry = Vec::new();
                for (peer, entry) in peers.iter_mut() {
                    if let Some(connected_at) = entry.connected_at {
                        if now.duration_since(connected_at) >= STABLE_CONNECTION {
                            entry.attempt = 0;
                        }
                        continue;
                    }
                    if now >= entry.next_retry {
                        retry.push(*peer);
                    }
                }
                for peer in retry {
                    dial_tracked(&mut swarm, peer, &mut peers);
                }
            },
            event = swarm.select_next_some() => {
                handle_event(event, &mut swarm, &control, &state, &mut peers, &revoked, max_connections, reconnect).await;
            }
        }
    }
}

fn track_addresses(peers: &mut HashMap<PeerId, TrackedPeer>, peer: PeerId, addresses: Vec<Multiaddr>) {
    let entry = peers.entry(peer).or_insert_with(|| TrackedPeer {
        addresses: Vec::new(), attempt: 0, next_retry: Instant::now(), connected_at: None,
        direct_attempted: false,
    });
    let mut changed = false;
    for address in addresses {
        if !entry.addresses.contains(&address) { entry.addresses.push(address); changed = true; }
    }
    if changed { entry.direct_attempted = false; }
    entry.next_retry = Instant::now();
}

fn learn_addresses(peers: &mut HashMap<PeerId, TrackedPeer>, peer: PeerId, addresses: Vec<Multiaddr>) {
    if let Some(entry) = peers.get_mut(&peer) {
        for address in addresses {
            if !entry.addresses.contains(&address) { entry.addresses.push(address); }
        }
        // A fresh direct candidate after an address/NAT change is worth trying before a relay.
        entry.direct_attempted = false;
    }
}

fn dial_tracked(swarm: &mut libp2p::Swarm<Behaviour>, peer: PeerId, peers: &mut HashMap<PeerId, TrackedPeer>) {
    let Some(entry) = peers.get_mut(&peer) else { return };
    if entry.addresses.is_empty() || swarm.is_connected(&peer) { return; }
    let mut addresses = entry.addresses.clone();
    addresses.sort_by_key(address_rank);
    let direct = addresses.iter().filter(|address| address_rank(address) < 4).cloned().collect::<Vec<_>>();
    if !entry.direct_attempted && !direct.is_empty() {
        addresses = direct;
        entry.direct_attempted = true;
    } else if !entry.direct_attempted {
        entry.direct_attempted = true;
    }
    let result = swarm.dial(
        DialOpts::peer_id(peer)
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .addresses(addresses)
            .build(),
    );
    schedule_retry(entry);
    if let Err(error) = result {
        tracing::debug!(%peer, %error, "dial request was not started");
    }
}

fn dial_once(swarm: &mut libp2p::Swarm<Behaviour>, peer: PeerId, mut addresses: Vec<Multiaddr>) {
    addresses.sort_by_key(address_rank);
    let direct = addresses.iter().filter(|address| address_rank(address) < 4).cloned().collect::<Vec<_>>();
    if !direct.is_empty() { addresses = direct; }
    if let Err(error) = swarm.dial(DialOpts::peer_id(peer).addresses(addresses).build()) {
        tracing::debug!(%peer, %error, "one-shot dial request was not started");
    }
}

fn schedule_retry(entry: &mut TrackedPeer) {
    let seconds = RETRY_STEPS[entry.attempt.min(RETRY_STEPS.len() - 1)];
    entry.attempt = entry.attempt.saturating_add(1);
    let jitter = rand::thread_rng().gen_range(0..=((seconds * 250) / 1000).max(1));
    entry.next_retry = Instant::now() + Duration::from_secs(seconds + jitter);
}

async fn handle_event(
    event: SwarmEvent<BehaviourEvent>,
    swarm: &mut libp2p::Swarm<Behaviour>,
    _control: &libp2p_stream::Control,
    state: &Arc<RwLock<SharedState>>,
    peers: &mut HashMap<PeerId, TrackedPeer>,
    revoked: &HashSet<PeerId>,
    max_connections: usize,
    reconnect: bool,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            let advertised = address.clone().with_p2p(*swarm.local_peer_id()).unwrap_or(address);
            state.write().await.listeners.insert(advertised.to_string());
        }
        SwarmEvent::ExpiredListenAddr { address, .. } => {
            state.write().await.listeners.remove(&address.clone().with_p2p(*swarm.local_peer_id()).unwrap_or(address).to_string());
        }
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
            if swarm.connected_peers().count() > max_connections {
                tracing::warn!(%peer_id, max_connections, "connection limit reached; closing newest connection");
                let _ = swarm.disconnect_peer_id(peer_id);
                return;
            }
            let relay = endpoint.is_relayed();
            let remote_address = endpoint.get_remote_address().clone();
            let address = remote_address.to_string();
            let path = {
                let mut shared = state.write().await;
                let path = if shared.hole_punched.contains(&peer_id) && !relay {
                    "HOLE-PUNCHED"
                } else {
                    route_label(&remote_address, relay)
                };
                shared.connections.insert(peer_id, ConnectionInfo { peer_id: peer_id.to_string(), address, path: path.to_owned(), latency_ms: None });
                path
            };
            if let Some(entry) = peers.get_mut(&peer_id) {
                entry.connected_at = Some(Instant::now());
                entry.attempt = 0;
            }
            tracing::debug!(%peer_id, %path, "connection established");
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            state.write().await.connections.remove(&peer_id);
            if reconnect && !revoked.contains(&peer_id) && let Some(entry) = peers.get_mut(&peer_id) {
                entry.connected_at = None;
                entry.direct_attempted = false;
                schedule_retry(entry);
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id: Some(peer_id), error, .. } => {
            tracing::debug!(%peer_id, %error, "outgoing connection failed");
            if reconnect && !revoked.contains(&peer_id) && let Some(entry) = peers.get_mut(&peer_id) { schedule_retry(entry); }
        }
        SwarmEvent::ListenerClosed { addresses, .. } => {
            for address in addresses {
                if address.iter().any(|part| matches!(part, libp2p::multiaddr::Protocol::P2pCircuit)) {
                    // A relay restart invalidates its reservation. Re-listening asks the relay for
                    // a fresh reservation without disrupting currently active direct streams.
                    if let Err(error) = swarm.listen_on(address.clone()) {
                        tracing::warn!(%address, %error, "unable to restore relay reservation");
                    }
                }
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
            let addresses = info.listen_addrs.into_iter()
                .filter(is_advertisable_peer_address)
                .filter_map(|address| pin_multiaddr(peer_id, address).ok()).collect::<Vec<_>>();
            if !addresses.is_empty() {
                if !revoked.contains(&peer_id) { learn_addresses(peers, peer_id, addresses.clone()); }
                let mut shared = state.write().await;
                shared.discovered.entry(peer_id).or_default().extend(addresses.into_iter().map(|a| a.to_string()));
            }
            // This is an observed candidate, not a trust assertion.
            swarm.add_external_address(info.observed_addr);
        }
        SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
            for (peer_id, address) in list {
                if is_advertisable_peer_address(&address) && let Ok(address) = pin_multiaddr(peer_id, address) {
                    if !revoked.contains(&peer_id) { learn_addresses(peers, peer_id, vec![address.clone()]); }
                    state.write().await.discovered.entry(peer_id).or_default().insert(address.to_string());
                }
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event { peer, result: Ok(rtt), .. })) => {
            if let Some(connection) = state.write().await.connections.get_mut(&peer) {
                connection.latency_ms = Some(rtt.as_millis().min(u128::from(u64::MAX)) as u64);
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::Autonat(autonat::Event::StatusChanged { new, .. })) => {
            state.write().await.nat_status = format!("{new:?}").to_uppercase();
        }
        SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) => {
            if event.result.is_ok() {
                let peer = event.remote_peer_id;
                let mut shared = state.write().await;
                shared.hole_punched.insert(peer);
                if let Some(connection) = shared.connections.get_mut(&peer) {
                    if connection.path != "RELAYED" {
                        connection.path = "HOLE-PUNCHED".to_owned();
                    }
                }
                tracing::info!(peer = %event.remote_peer_id, "direct connection upgrade succeeded");
            }
        }
        _ => {}
    }
}

fn spawn_incoming_forwarder(
    mut incoming: libp2p_stream::IncomingStreams,
    sender: mpsc::Sender<Incoming>,
    protocol: &'static str,
) {
    tokio::spawn(async move {
        while let Some((peer, stream)) = incoming.next().await {
            // send awaits the bounded application queue, intentionally propagating backpressure.
            if sender.send(Incoming { peer, protocol: protocol.to_owned(), stream: stream.compat() }).await.is_err() {
                return;
            }
        }
    });
}

fn relay_limits() -> relay::Config {
    relay::Config {
        max_reservations: 64,
        max_reservations_per_peer: 2,
        reservation_duration: Duration::from_secs(60 * 30),
        reservation_rate_limiters: Vec::new(),
        max_circuits: 16,
        max_circuits_per_peer: 2,
        max_circuit_duration: Duration::from_secs(120),
        max_circuit_bytes: 128 * 1024,
        circuit_src_rate_limiters: Vec::new(),
    }
    .reservation_rate_per_peer(NonZeroU32::new(10).expect("nonzero"), Duration::from_secs(60))
    .reservation_rate_per_ip(NonZeroU32::new(20).expect("nonzero"), Duration::from_secs(60))
    .circuit_src_per_peer(NonZeroU32::new(10).expect("nonzero"), Duration::from_secs(60))
    .circuit_src_per_ip(NonZeroU32::new(20).expect("nonzero"), Duration::from_secs(60))
}

fn dial_configured_node(swarm: &mut libp2p::Swarm<Behaviour>, raw: &str) -> Result<()> {
    let address: Multiaddr = raw.parse().with_context(|| format!("invalid multiaddr {raw}"))?;
    let Some(libp2p::multiaddr::Protocol::P2p(peer)) = address.iter().last() else {
        bail!("configured relay/bootstrap address must end in /p2p/<peer-id>");
    };
    swarm.dial(DialOpts::peer_id(peer.into()).addresses(vec![address]).build())?;
    Ok(())
}

fn configure_relay_node(swarm: &mut libp2p::Swarm<Behaviour>, raw: &str) -> Result<()> {
    let address: Multiaddr = raw.parse().with_context(|| format!("invalid relay multiaddr {raw}"))?;
    let Some(libp2p::multiaddr::Protocol::P2p(peer)) = address.iter().last() else {
        bail!("relay address must end in /p2p/<peer-id>");
    };
    let peer: PeerId = peer.into();
    swarm.dial(DialOpts::peer_id(peer).addresses(vec![address.clone()]).build())?;
    // A circuit listener requests a bounded relay-v2 reservation. DCUtR receives the
    // resulting relayed connection and attempts a verified direct upgrade automatically.
    swarm.listen_on(address.with(libp2p::multiaddr::Protocol::P2pCircuit))?;
    Ok(())
}

fn ensure_protocol(protocol: &str) -> Result<()> {
    if PROTOCOLS.contains(&protocol) { Ok(()) } else { bail!("unsupported OpenGate protocol {protocol}") }
}

fn protocol_stream(protocol: &str) -> Result<StreamProtocol> {
    Ok(match protocol {
        CONTROL_PROTOCOL => StreamProtocol::new(CONTROL_PROTOCOL),
        TERMINAL_PROTOCOL => StreamProtocol::new(TERMINAL_PROTOCOL),
        FILES_PROTOCOL => StreamProtocol::new(FILES_PROTOCOL),
        TCP_FORWARD_PROTOCOL => StreamProtocol::new(TCP_FORWARD_PROTOCOL),
        DESKTOP_PROTOCOL => StreamProtocol::new(DESKTOP_PROTOCOL),
        HEARTBEAT_PROTOCOL => StreamProtocol::new(HEARTBEAT_PROTOCOL),
        CLIPBOARD_PROTOCOL => StreamProtocol::new(CLIPBOARD_PROTOCOL),
        _ => bail!("unsupported OpenGate protocol {protocol}"),
    })
}

fn pinned_addresses(peer: PeerId, addresses: &[String]) -> Result<Vec<Multiaddr>> {
    addresses.iter().map(|raw| {
        let address = raw.parse().with_context(|| format!("invalid multiaddr {raw}"))?;
        pin_multiaddr(peer, address)
    }).collect()
}

fn pin_multiaddr(peer: PeerId, address: Multiaddr) -> Result<Multiaddr> {
    // Relay candidates contain the relay peer id before `p2p-circuit`; the final p2p
    // component is the destination identity to pin. Direct candidates have one component.
    let advertised = address.iter().filter_map(|component| match component {
        libp2p::multiaddr::Protocol::P2p(actual) => Some(PeerId::from(actual)),
        _ => None,
    }).last();
    if let Some(actual) = advertised {
        if actual != peer { bail!("address destination peer id {actual} does not match expected {peer}"); }
    }
    Ok(address.clone().with_p2p(peer).unwrap_or(address))
}

fn address_rank(address: &Multiaddr) -> u8 {
    use libp2p::multiaddr::Protocol;
    let components = address.iter().collect::<Vec<_>>();
    let relayed = components.iter().any(|p| matches!(p, Protocol::P2pCircuit));
    if relayed { return 4; }
    if components.iter().any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_private() || ip.is_loopback())) { return 0; }
    if components.iter().any(|p| matches!(p, Protocol::Ip6(ip) if ip.is_loopback() || ip.is_unique_local())) { return 0; }
    if components.iter().any(|p| matches!(p, Protocol::Ip6(_))) { return 1; }
    2
}

fn is_advertisable_peer_address(address: &Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    !address.iter().any(|part| match part {
        Protocol::Ip4(ip) => ip.is_unspecified(),
        Protocol::Ip6(ip) => ip.is_unspecified(),
        _ => false,
    })
}

fn route_label(address: &Multiaddr, relayed: bool) -> &'static str {
    use libp2p::multiaddr::Protocol;
    if relayed {
        return "RELAYED";
    }
    for part in address.iter() {
        match part {
            Protocol::Ip4(ip) if ip.is_private() || ip.is_loopback() || ip.is_link_local() => return "LAN",
            Protocol::Ip6(ip) if ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local() => return "LAN",
            Protocol::Ip6(_) => return "IPv6 DIRECT",
            _ => {}
        }
    }
    "DIRECT"
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn peer_id_is_pinned_on_all_dial_candidates() {
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        let address = pin_multiaddr(peer, "/ip4/127.0.0.1/udp/9000/quic-v1".parse().unwrap()).unwrap();
        assert!(address.to_string().ends_with(&format!("/p2p/{peer}")));
        let other = identity::Keypair::generate_ed25519().public().to_peer_id();
        assert!(pin_multiaddr(peer, format!("/ip4/127.0.0.1/tcp/1/p2p/{other}").parse().unwrap()).is_err());
    }

    #[test]
    fn direct_addresses_rank_before_relayed_ones() {
        let direct: Multiaddr = "/ip4/8.8.8.8/udp/443/quic-v1".parse().unwrap();
        let relay: Multiaddr = "/ip4/8.8.8.8/tcp/443/p2p-circuit".parse().unwrap();
        assert!(address_rank(&direct) < address_rank(&relay));
        assert_eq!(route_label(&"/ip4/8.8.8.8/udp/443/quic-v1".parse().unwrap(), false), "DIRECT");
    }

    #[tokio::test]
    async fn two_nodes_open_a_pinned_quic_stream() {
        let key_a = identity::Keypair::generate_ed25519();
        let key_b = identity::Keypair::generate_ed25519();
        let peer_b = key_b.public().to_peer_id();
        let (node_a, _incoming_a) = Node::start(key_a, NetworkOptions::default()).await.unwrap();
        let (node_b, mut incoming_b) = Node::start(key_b, NetworkOptions::default()).await.unwrap();

        let addresses = timeout(Duration::from_secs(5), async {
            loop {
                let listeners = node_b.snapshot().await.unwrap().listeners;
                if !listeners.is_empty() { break listeners; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.expect("node B did not publish a listener");

        let mut outbound = timeout(
            Duration::from_secs(10),
            node_a.open(peer_b, CONTROL_PROTOCOL, &addresses),
        ).await.expect("opening stream timed out").expect("open pinned stream");
        let mut inbound = timeout(Duration::from_secs(10), incoming_b.recv())
            .await.expect("incoming stream timed out").expect("incoming queue closed");

        outbound.write_all(b"open-gate").await.unwrap();
        let mut received = [0u8; 9];
        inbound.stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"open-gate");
        node_a.shutdown().await.unwrap();
        node_b.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn three_nodes_reserve_and_transfer_over_a_relay_candidate() {
        let relay_key = identity::Keypair::generate_ed25519();
        let relay_peer = relay_key.public().to_peer_id();
        let (relay, _relay_incoming) = Node::start(
            relay_key,
            NetworkOptions { relay_server: true, ..NetworkOptions::default() },
        ).await.unwrap();
        let relay_address = wait_for_listener(&relay, |address| !address.contains("p2p-circuit")).await;
        assert!(relay_address.ends_with(&format!("/p2p/{relay_peer}")));

        let key_b = identity::Keypair::generate_ed25519();
        let peer_b = key_b.public().to_peer_id();
        let (node_b, mut incoming_b) = Node::start(
            key_b,
            NetworkOptions { relay_nodes: vec![relay_address.clone()], ..NetworkOptions::default() },
        ).await.unwrap();
        let relay_candidate = wait_for_listener(&node_b, |address| address.contains("p2p-circuit")).await;
        assert!(relay_candidate.ends_with(&format!("/p2p/{peer_b}")));

        let (node_a, _incoming_a) = Node::start(
            identity::Keypair::generate_ed25519(),
            NetworkOptions { relay_nodes: vec![relay_address], ..NetworkOptions::default() },
        ).await.unwrap();
        let mut outbound = timeout(Duration::from_secs(15), node_a.open(peer_b, CONTROL_PROTOCOL, &[relay_candidate]))
            .await.expect("opening relayed stream timed out").expect("open relayed stream");
        let mut inbound = timeout(Duration::from_secs(15), incoming_b.recv())
            .await.expect("relayed inbound stream timed out").expect("incoming queue closed");
        outbound.write_all(b"via-relay").await.unwrap();
        let mut received = [0u8; 9];
        inbound.stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"via-relay");

        node_a.shutdown().await.unwrap();
        node_b.shutdown().await.unwrap();
        relay.shutdown().await.unwrap();
    }

    async fn wait_for_listener(node: &Node, predicate: impl Fn(&str) -> bool) -> String {
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(address) = node.snapshot().await.unwrap().listeners.into_iter().find(|address| predicate(address)) {
                    return address;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.expect("listener was not published")
    }
}
