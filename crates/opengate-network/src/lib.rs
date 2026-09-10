//! The authenticated transport layer used by OpenGate.
//!
//! A successful libp2p connection proves the remote [`PeerId`], but deliberately does
//! not grant application permissions. Callers must consult the trust store for every
//! returned stream. Discovery addresses are only dial candidates: explicit addresses are
//! pinned to the expected peer id before use.
//!
//! QUIC is preferred, with TCP/Noise/Yamux and DNS as fallbacks. Relay v2 and DCUtR are
//! enabled for self-hosted relays. Relay servers use bounded reservations (64), circuits
//! (16), circuit duration (one hour), circuit bytes (1 GiB), 8 MiB/s per circuit, 64 MiB/s shared
//! across circuits, and libp2p's per-peer and per-IP admission rate limiters. These intentionally conservative defaults prevent a relay
//! from becoming an unbounded traffic service; long-running application transfers should
//! use direct connections after DCUtR has upgraded them.

use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, SwarmBuilder, autonat, dcutr, identify, identity, mdns, noise, ping, relay,
    swarm::{
        NetworkBehaviour, StreamProtocol, SwarmEvent,
        behaviour::toggle::Toggle,
        dial_opts::{DialOpts, PeerCondition},
    },
    tcp, yamux,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{RwLock, mpsc, oneshot},
    time::{MissedTickBehavior, interval, timeout},
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

/// Relay admission controls supported by libp2p Circuit Relay v2.
///
/// `max_circuit_bytes` is a hard cumulative byte cap for each circuit. The bandwidth limits pace
/// opaque encrypted circuit bytes with a fixed-size relay buffer: `max_circuit_bandwidth_bytes_per_second`
/// is shared across both directions of one circuit and `max_total_bandwidth_bytes_per_second` is
/// shared by every circuit on this relay. Existing circuit count, duration, byte caps, and
/// admission controls remain in force.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayLimits {
    pub max_reservations: usize,
    pub max_reservations_per_peer: usize,
    pub reservation_duration_secs: u64,
    pub max_circuits: usize,
    pub max_circuits_per_peer: usize,
    pub max_circuit_duration_secs: u64,
    pub max_circuit_bytes: u64,
    /// Maximum opaque bytes per second for one relayed circuit, across both directions.
    pub max_circuit_bandwidth_bytes_per_second: u64,
    /// Maximum opaque bytes per second shared by all circuits served by this relay.
    pub max_total_bandwidth_bytes_per_second: u64,
    /// Maximum reservation requests admitted for each peer during the interval.
    pub reservation_rate_per_peer: u32,
    /// Maximum reservation requests admitted for each source IP during the interval.
    pub reservation_rate_per_ip: u32,
    /// Maximum circuit requests admitted for each peer during the interval.
    pub circuit_rate_per_peer: u32,
    /// Maximum circuit requests admitted for each source IP during the interval.
    pub circuit_rate_per_ip: u32,
    pub rate_interval_secs: u64,
}

impl RelayLimits {
    pub fn validate(&self) -> Result<()> {
        relay_limits(self).map(|_| ())
    }
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_reservations: 64,
            max_reservations_per_peer: 2,
            reservation_duration_secs: 60 * 30,
            max_circuits: 16,
            max_circuits_per_peer: 2,
            max_circuit_duration_secs: 60 * 60,
            max_circuit_bytes: 1024 * 1024 * 1024,
            max_circuit_bandwidth_bytes_per_second: 8 * 1024 * 1024,
            max_total_bandwidth_bytes_per_second: 64 * 1024 * 1024,
            reservation_rate_per_peer: 10,
            reservation_rate_per_ip: 20,
            circuit_rate_per_peer: 10,
            circuit_rate_per_ip: 20,
            rate_interval_secs: 60,
        }
    }
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
    /// Applied only while this node serves Circuit Relay v2 traffic.
    pub relay_limits: RelayLimits,
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
            relay_limits: RelayLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub peer_id: String,
    pub listeners: Vec<String>,
    pub connections: Vec<ConnectionInfo>,
    pub discovered: Vec<DiscoveredPeer>,
    /// Saved/tracked peers and their current connection state. Discovery alone never grants trust.
    pub peers: Vec<PeerState>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    pub peer_id: String,
    /// DISCONNECTED, DIALING, CONNECTED, or RECONNECTING.
    pub state: String,
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
        Self::start_inner(key, options, true, true).await
    }

    async fn start_inner(
        key: identity::Keypair,
        options: NetworkOptions,
        enable_mdns: bool,
        enable_dcutr: bool,
    ) -> Result<(Node, mpsc::Receiver<Incoming>)> {
        let peer_id = key.public().to_peer_id();
        let runtime = RuntimeConfig {
            max_connections: options.max_connections.max(1) as usize,
            reconnect: options.reconnect,
            relay_nodes: options.relay_nodes.clone(),
            bootstrap_nodes: options.bootstrap_nodes.clone(),
        };
        let relay_config = options
            .relay_server
            .then(|| relay_limits(&options.relay_limits))
            .transpose()?;

        let mut swarm = SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .context("configure TCP Noise/Yamux transport")?
            .with_quic_config(|mut config| {
                // A file receiver may wait for durable disk writes. Advertise a
                // bounded window so a fast sender cannot accumulate thousands
                // of packet fragments while the application is backpressured.
                config.max_stream_data = 512 * 1024;
                config.max_connection_data = 8 * 1024 * 1024;
                config
            })
            .with_dns()
            .context("configure DNS transport")?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .context("configure relay client transport")?
            .with_behaviour(
                move |key,
                      relay_client|
                      -> std::result::Result<
                    Behaviour,
                    Box<dyn std::error::Error + Send + Sync>,
                > {
                    let local_peer = key.public().to_peer_id();
                    let mdns = enable_mdns
                        .then(|| mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer))
                        .transpose()?;
                    Ok(Behaviour {
                        stream: libp2p_stream::Behaviour::new(),
                        // Bind addresses such as 0.0.0.0 are not dial candidates. Identify shares
                        // only confirmed external addresses; snapshots filter local candidates too.
                        identify: identify::Behaviour::new(
                            identify::Config::new_with_signed_peer_record(
                                "/opengate/1".to_owned(),
                                key,
                            )
                            .with_hide_listen_addrs(true),
                        ),
                        ping: ping::Behaviour::new(
                            ping::Config::new()
                                .with_interval(Duration::from_secs(10))
                                .with_timeout(Duration::from_secs(30)),
                        ),
                        mdns: Toggle::from(mdns),
                        autonat: autonat::Behaviour::new(local_peer, autonat::Config::default()),
                        relay_client,
                        relay_server: Toggle::from(
                            relay_config.map(|cfg| relay::Behaviour::new(local_peer, cfg)),
                        ),
                        dcutr: Toggle::from(
                            enable_dcutr.then(|| dcutr::Behaviour::new(local_peer)),
                        ),
                    })
                },
            )
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
                .listen_on(
                    address
                        .parse()
                        .with_context(|| format!("invalid listen address {address}"))?,
                )
                .with_context(|| format!("listen on {address}"))?;
        }

        let state = Arc::new(RwLock::new(SharedState::new(peer_id)));
        let (command_tx, command_rx) = mpsc::channel(128);
        let node = Node {
            commands: command_tx,
            state: state.clone(),
        };
        tokio::spawn(run_swarm(swarm, control, command_rx, state, runtime));
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
        reply_rx
            .await
            .map_err(|_| anyhow!("network node stopped opening stream"))?
    }

    pub async fn add_peer(&self, peer: PeerId, addresses: Vec<String>) -> Result<()> {
        let addresses = pinned_addresses(peer, &addresses)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::AddPeer {
                peer,
                addresses,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("network node has stopped"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("network node stopped adding peer"))?
    }

    pub async fn disconnect(&self, peer: PeerId) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Disconnect {
                peer,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("network node has stopped"))?;
        reply_rx
            .await
            .map_err(|_| anyhow!("network node stopped disconnecting peer"))?
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
        reply_rx
            .await
            .map_err(|_| anyhow!("network node stopped during shutdown"))
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
    dcutr: Toggle<dcutr::Behaviour>,
}

enum Command {
    Open {
        peer: PeerId,
        protocol: String,
        addresses: Vec<Multiaddr>,
        reply: oneshot::Sender<Result<PeerStream>>,
    },
    AddPeer {
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        reply: oneshot::Sender<Result<()>>,
    },
    Disconnect {
        peer: PeerId,
        reply: oneshot::Sender<Result<()>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

#[derive(Default)]
struct SharedState {
    peer_id: String,
    listeners: HashSet<String>,
    connections: HashMap<PeerId, ConnectionInfo>,
    discovered: HashMap<PeerId, HashSet<String>>,
    peers: HashMap<PeerId, String>,
    nat_status: String,
    hole_punched: HashSet<PeerId>,
}

impl SharedState {
    fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id: peer_id.to_string(),
            nat_status: "UNKNOWN".to_owned(),
            ..Self::default()
        }
    }

    fn snapshot(&self) -> Snapshot {
        let mut listeners: Vec<_> = self.listeners.iter().cloned().collect();
        listeners.sort();
        let mut connections: Vec<_> = self.connections.values().cloned().collect();
        connections.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        let mut discovered: Vec<_> = self
            .discovered
            .iter()
            .map(|(peer, addresses)| {
                let mut addresses: Vec<_> = addresses.iter().cloned().collect();
                addresses.sort();
                DiscoveredPeer {
                    peer_id: peer.to_string(),
                    addresses,
                }
            })
            .collect();
        discovered.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        let mut peers: Vec<_> = self
            .peers
            .iter()
            .map(|(peer_id, state)| PeerState {
                peer_id: peer_id.to_string(),
                state: state.clone(),
            })
            .collect();
        peers.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        Snapshot {
            peer_id: self.peer_id.clone(),
            listeners,
            connections,
            discovered,
            peers,
            nat_status: self.nat_status.clone(),
        }
    }

    fn set_peer_state(&mut self, peer: PeerId, connection_state: &str) {
        self.peers.insert(peer, connection_state.to_owned());
    }
}

struct TrackedPeer {
    addresses: Vec<Multiaddr>,
    attempt: usize,
    next_retry: Instant,
    connected_at: Option<Instant>,
    direct_attempted: bool,
}

struct RuntimeConfig {
    max_connections: usize,
    reconnect: bool,
    relay_nodes: Vec<String>,
    bootstrap_nodes: Vec<String>,
}

async fn run_swarm(
    mut swarm: libp2p::Swarm<Behaviour>,
    control: libp2p_stream::Control,
    mut commands: mpsc::Receiver<Command>,
    state: Arc<RwLock<SharedState>>,
    runtime: RuntimeConfig,
) {
    let mut peers: HashMap<PeerId, TrackedPeer> = HashMap::new();
    let mut revoked = HashSet::new();
    let mut shutdown_reply = None;
    let mut tick = interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    for address in runtime.relay_nodes.clone() {
        if let Err(error) = configure_relay_node(&mut swarm, &address) {
            tracing::warn!(%address, %error, "ignoring invalid configured relay node");
        }
    }
    for address in runtime.bootstrap_nodes.clone() {
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
                            Ok(protocol) => match timeout(OPEN_TIMEOUT, async {
                                loop {
                                    match control.open_stream(peer, protocol.clone()).await {
                                        Ok(stream) => break Ok(FuturesAsyncReadCompatExt::compat(stream)),
                                        Err(libp2p_stream::OpenStreamError::Io(error)) => {
                                            // After a peer restarts, a newly established connection
                                            // can coexist briefly with the old timed-out one. Retry
                                            // transport stream creation; no application request or
                                            // shell command has been sent at this point.
                                            tracing::debug!(%peer, %error, "retrying stream creation after transport loss");
                                            tokio::time::sleep(Duration::from_millis(250)).await;
                                        }
                                        Err(error) => break Err(anyhow!("open stream to {peer}: {error}")),
                                    }
                                }
                            }).await {
                                Ok(result) => result,
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
                    state.write().await.set_peer_state(peer, "DIALING");
                    let _ = reply.send(Ok(()));
                }
                Some(Command::Disconnect { peer, reply }) => {
                    // Revocation/removal is represented by forgetting the tracked peer. A later
                    // ConnectionClosed event therefore cannot schedule it again.
                    peers.remove(&peer);
                    revoked.insert(peer);
                    let _ = swarm.disconnect_peer_id(peer);
                    state.write().await.set_peer_state(peer, "DISCONNECTED");
                    let _ = reply.send(Ok(()));
                }
                Some(Command::Shutdown { reply }) => {
                    for peer in swarm.connected_peers().copied().collect::<Vec<_>>() {
                        let _ = swarm.disconnect_peer_id(peer);
                    }
                    // A caller may immediately restart on the same port. Confirm shutdown only
                    // after the swarm (and its transport listeners) has been dropped.
                    shutdown_reply = Some(reply);
                    break;
                }
                None => break,
            },
            _ = tick.tick(), if runtime.reconnect => {
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
                handle_event(event, &mut swarm, &state, &mut peers, &revoked, &runtime).await;
            }
        }
    }
    drop(swarm);
    if let Some(reply) = shutdown_reply {
        let _ = reply.send(());
    }
}

fn track_addresses(
    peers: &mut HashMap<PeerId, TrackedPeer>,
    peer: PeerId,
    addresses: Vec<Multiaddr>,
) {
    let entry = peers.entry(peer).or_insert_with(|| TrackedPeer {
        addresses: Vec::new(),
        attempt: 0,
        next_retry: Instant::now(),
        connected_at: None,
        direct_attempted: false,
    });
    let mut changed = false;
    for address in addresses {
        if !entry.addresses.contains(&address) {
            entry.addresses.push(address);
            changed = true;
        }
    }
    if changed {
        entry.direct_attempted = false;
    }
    entry.next_retry = Instant::now();
}

fn learn_addresses(
    peers: &mut HashMap<PeerId, TrackedPeer>,
    peer: PeerId,
    addresses: Vec<Multiaddr>,
) {
    if let Some(entry) = peers.get_mut(&peer) {
        for address in addresses {
            if !entry.addresses.contains(&address) {
                entry.addresses.push(address);
            }
        }
        // A fresh direct candidate after an address/NAT change is worth trying before a relay.
        entry.direct_attempted = false;
    }
}

fn dial_tracked(
    swarm: &mut libp2p::Swarm<Behaviour>,
    peer: PeerId,
    peers: &mut HashMap<PeerId, TrackedPeer>,
) {
    let Some(entry) = peers.get_mut(&peer) else {
        return;
    };
    if entry.addresses.is_empty() || swarm.is_connected(&peer) {
        return;
    }
    let mut addresses = entry.addresses.clone();
    addresses.sort_by_key(address_rank);
    let direct = addresses
        .iter()
        .filter(|address| address_rank(address) < 4)
        .cloned()
        .collect::<Vec<_>>();
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
    let direct = addresses
        .iter()
        .filter(|address| address_rank(address) < 4)
        .cloned()
        .collect::<Vec<_>>();
    if !direct.is_empty() {
        addresses = direct;
    }
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
    state: &Arc<RwLock<SharedState>>,
    peers: &mut HashMap<PeerId, TrackedPeer>,
    revoked: &HashSet<PeerId>,
    runtime: &RuntimeConfig,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            if is_advertisable_peer_address(&address) {
                let advertised = address
                    .clone()
                    .with_p2p(*swarm.local_peer_id())
                    .unwrap_or_else(|_| address.clone());
                state.write().await.listeners.insert(advertised.to_string());
                // Relay-v2 reservations must contain a real relay candidate. A relay bound to
                // an explicit address can advertise that address immediately; wildcard binds
                // stay out of both snapshots and reservations until AutoNAT/Identify confirms
                // an externally reachable address.
                if swarm.behaviour().relay_server.is_enabled() {
                    swarm.add_external_address(address);
                }
            }
        }
        SwarmEvent::ExpiredListenAddr { address, .. } => {
            if is_advertisable_peer_address(&address) {
                state.write().await.listeners.remove(
                    &address
                        .clone()
                        .with_p2p(*swarm.local_peer_id())
                        .unwrap_or(address)
                        .to_string(),
                );
            }
        }
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            if swarm.connected_peers().count() > runtime.max_connections {
                tracing::warn!(%peer_id, max_connections = runtime.max_connections, "connection limit reached; closing newest connection");
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
                shared.connections.insert(
                    peer_id,
                    ConnectionInfo {
                        peer_id: peer_id.to_string(),
                        address,
                        path: path.to_owned(),
                        latency_ms: None,
                    },
                );
                path
            };
            if let Some(entry) = peers.get_mut(&peer_id) {
                entry.connected_at = Some(Instant::now());
                entry.attempt = 0;
            }
            state.write().await.set_peer_state(peer_id, "CONNECTED");
            tracing::debug!(%peer_id, %path, "connection established");
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            cause,
            ..
        } => {
            tracing::debug!(%peer_id, ?cause, num_established, "connection closed");
            // A DCUtR direct connection and its relayed predecessor can coexist. Losing one
            // must not report the peer as offline, schedule a redundant reconnect, or disturb
            // application streams that remain on the other connection.
            if num_established == 0 {
                state.write().await.connections.remove(&peer_id);
                if runtime.reconnect
                    && !revoked.contains(&peer_id)
                    && let Some(entry) = peers.get_mut(&peer_id)
                {
                    entry.connected_at = None;
                    entry.direct_attempted = false;
                    schedule_retry(entry);
                    state.write().await.set_peer_state(peer_id, "RECONNECTING");
                } else if !revoked.contains(&peer_id) {
                    state.write().await.set_peer_state(peer_id, "DISCONNECTED");
                }
            }
        }
        SwarmEvent::OutgoingConnectionError {
            peer_id: Some(peer_id),
            error,
            ..
        } => {
            tracing::debug!(%peer_id, %error, "outgoing connection failed");
            if runtime.reconnect
                && !revoked.contains(&peer_id)
                && let Some(entry) = peers.get_mut(&peer_id)
            {
                schedule_retry(entry);
                state.write().await.set_peer_state(peer_id, "RECONNECTING");
            }
        }
        SwarmEvent::ListenerClosed {
            addresses, reason, ..
        } => {
            tracing::debug!(?addresses, ?reason, "listener closed");
            for address in addresses {
                if address
                    .iter()
                    .any(|part| matches!(part, libp2p::multiaddr::Protocol::P2pCircuit))
                {
                    // A relay restart invalidates its reservation. Re-listening asks the relay for
                    // a fresh reservation without disrupting currently active direct streams.
                    if let Err(error) = swarm.listen_on(address.clone()) {
                        tracing::warn!(%address, %error, "unable to restore relay reservation");
                    }
                }
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            let addresses = info
                .listen_addrs
                .into_iter()
                .filter(is_advertisable_peer_address)
                .filter_map(|address| pin_multiaddr(peer_id, address).ok())
                .collect::<Vec<_>>();
            if !addresses.is_empty() {
                if !revoked.contains(&peer_id) {
                    learn_addresses(peers, peer_id, addresses.clone());
                }
                let mut shared = state.write().await;
                shared
                    .discovered
                    .entry(peer_id)
                    .or_default()
                    .extend(addresses.into_iter().map(|a| a.to_string()));
            }
            // This is an observed candidate, not a trust assertion.
            swarm.add_external_address(info.observed_addr);
        }
        SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
            for (peer_id, address) in list {
                if is_advertisable_peer_address(&address)
                    && let Ok(address) = pin_multiaddr(peer_id, address)
                {
                    if !revoked.contains(&peer_id) {
                        learn_addresses(peers, peer_id, vec![address.clone()]);
                    }
                    state
                        .write()
                        .await
                        .discovered
                        .entry(peer_id)
                        .or_default()
                        .insert(address.to_string());
                }
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event {
            peer,
            result: Ok(rtt),
            ..
        })) => {
            if let Some(connection) = state.write().await.connections.get_mut(&peer) {
                connection.latency_ms = Some(rtt.as_millis().min(u128::from(u64::MAX)) as u64);
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::Autonat(autonat::Event::StatusChanged {
            new,
            ..
        })) => {
            state.write().await.nat_status = format!("{new:?}").to_uppercase();
        }
        SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) => {
            if event.result.is_ok() {
                let peer = event.remote_peer_id;
                let mut shared = state.write().await;
                shared.hole_punched.insert(peer);
                if let Some(connection) = shared.connections.get_mut(&peer)
                    && connection.path != "RELAYED"
                {
                    connection.path = "HOLE-PUNCHED".to_owned();
                }
                tracing::info!(peer = %event.remote_peer_id, "direct connection upgrade succeeded");
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::RelayClient(event)) => {
            tracing::debug!(?event, "relay client event");
        }
        SwarmEvent::ListenerError { error, .. } => eprintln!("listener error: {error}"),
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
            if sender
                .send(Incoming {
                    peer,
                    protocol: protocol.to_owned(),
                    stream: stream.compat(),
                })
                .await
                .is_err()
            {
                return;
            }
        }
    });
}

fn relay_limits(limits: &RelayLimits) -> Result<relay::Config> {
    if limits.max_circuit_duration_secs == 0 {
        bail!("relay max_circuit_duration_secs must be greater than zero");
    }
    if limits.max_circuit_duration_secs > u64::from(u32::MAX) {
        bail!("relay max_circuit_duration_secs cannot exceed {}", u32::MAX);
    }
    if limits.max_circuit_bytes == 0 {
        bail!("relay max_circuit_bytes must be greater than zero; libp2p treats zero as unlimited");
    }
    if limits.max_circuit_bandwidth_bytes_per_second == 0 {
        bail!("relay max_circuit_bandwidth_bytes_per_second must be greater than zero");
    }
    if limits.max_total_bandwidth_bytes_per_second == 0 {
        bail!("relay max_total_bandwidth_bytes_per_second must be greater than zero");
    }
    if limits.rate_interval_secs == 0 {
        bail!("relay rate_interval_secs must be greater than zero");
    }
    let interval = Duration::from_secs(limits.rate_interval_secs);
    Ok(relay::Config {
        max_reservations: limits.max_reservations,
        max_reservations_per_peer: limits.max_reservations_per_peer,
        reservation_duration: Duration::from_secs(limits.reservation_duration_secs),
        reservation_rate_limiters: Vec::new(),
        max_circuits: limits.max_circuits,
        max_circuits_per_peer: limits.max_circuits_per_peer,
        max_circuit_duration: Duration::from_secs(limits.max_circuit_duration_secs),
        max_circuit_bytes: limits.max_circuit_bytes,
        max_circuit_bytes_per_second: limits.max_circuit_bandwidth_bytes_per_second,
        max_total_circuit_bytes_per_second: limits.max_total_bandwidth_bytes_per_second,
        circuit_src_rate_limiters: Vec::new(),
    }
    .reservation_rate_per_peer(nonzero_rate(limits.reservation_rate_per_peer)?, interval)
    .reservation_rate_per_ip(nonzero_rate(limits.reservation_rate_per_ip)?, interval)
    .circuit_src_per_peer(nonzero_rate(limits.circuit_rate_per_peer)?, interval)
    .circuit_src_per_ip(nonzero_rate(limits.circuit_rate_per_ip)?, interval))
}

fn nonzero_rate(limit: u32) -> Result<NonZeroU32> {
    NonZeroU32::new(limit).ok_or_else(|| anyhow!("relay rate limits must be greater than zero"))
}

fn dial_configured_node(swarm: &mut libp2p::Swarm<Behaviour>, raw: &str) -> Result<()> {
    let address: Multiaddr = raw
        .parse()
        .with_context(|| format!("invalid multiaddr {raw}"))?;
    let Some(libp2p::multiaddr::Protocol::P2p(peer)) = address.iter().last() else {
        bail!("configured relay/bootstrap address must end in /p2p/<peer-id>");
    };
    swarm.dial(DialOpts::peer_id(peer).addresses(vec![address]).build())?;
    Ok(())
}

fn configure_relay_node(swarm: &mut libp2p::Swarm<Behaviour>, raw: &str) -> Result<()> {
    let address: Multiaddr = raw
        .parse()
        .with_context(|| format!("invalid relay multiaddr {raw}"))?;
    let Some(libp2p::multiaddr::Protocol::P2p(_)) = address.iter().last() else {
        bail!("relay address must end in /p2p/<peer-id>");
    };
    // A circuit listener requests a bounded relay-v2 reservation. The relay peer identity must
    // remain immediately before `p2p-circuit`; stripping it produces an invalid reservation.
    // DCUtR receives the resulting relayed connection and attempts a verified direct upgrade.
    swarm.listen_on(address.with(libp2p::multiaddr::Protocol::P2pCircuit))?;
    Ok(())
}

fn ensure_protocol(protocol: &str) -> Result<()> {
    if PROTOCOLS.contains(&protocol) {
        Ok(())
    } else {
        bail!("unsupported OpenGate protocol {protocol}")
    }
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
    addresses
        .iter()
        .map(|raw| {
            let address = raw
                .parse()
                .with_context(|| format!("invalid multiaddr {raw}"))?;
            pin_multiaddr(peer, address)
        })
        .collect()
}

fn pin_multiaddr(peer: PeerId, address: Multiaddr) -> Result<Multiaddr> {
    // Relay candidates contain the relay peer id before `p2p-circuit`; the final p2p
    // component is the destination identity to pin. Direct candidates have one component.
    let advertised = address
        .iter()
        .filter_map(|component| match component {
            libp2p::multiaddr::Protocol::P2p(actual) => Some(actual),
            _ => None,
        })
        .last();
    if let Some(actual) = advertised
        && actual != peer
    {
        bail!("address destination peer id {actual} does not match expected {peer}");
    }
    Ok(address.clone().with_p2p(peer).unwrap_or(address))
}

fn address_rank(address: &Multiaddr) -> u8 {
    use libp2p::multiaddr::Protocol;
    let components = address.iter().collect::<Vec<_>>();
    let relayed = components.iter().any(|p| matches!(p, Protocol::P2pCircuit));
    if relayed {
        return 4;
    }
    if components
        .iter()
        .any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_private() || ip.is_loopback()))
    {
        return 0;
    }
    if components
        .iter()
        .any(|p| matches!(p, Protocol::Ip6(ip) if ip.is_loopback() || ip.is_unique_local()))
    {
        return 0;
    }
    if components.iter().any(|p| matches!(p, Protocol::Ip6(_))) {
        return 1;
    }
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
            Protocol::Ip4(ip) if ip.is_private() || ip.is_loopback() || ip.is_link_local() => {
                return "LAN";
            }
            Protocol::Ip6(ip)
                if ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local() =>
            {
                return "LAN";
            }
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
        let address =
            pin_multiaddr(peer, "/ip4/127.0.0.1/udp/9000/quic-v1".parse().unwrap()).unwrap();
        assert!(address.to_string().ends_with(&format!("/p2p/{peer}")));
        let other = identity::Keypair::generate_ed25519().public().to_peer_id();
        assert!(
            pin_multiaddr(
                peer,
                format!("/ip4/127.0.0.1/tcp/1/p2p/{other}").parse().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn direct_addresses_rank_before_relayed_ones() {
        let direct: Multiaddr = "/ip4/8.8.8.8/udp/443/quic-v1".parse().unwrap();
        let relay: Multiaddr = "/ip4/8.8.8.8/tcp/443/p2p-circuit".parse().unwrap();
        assert!(address_rank(&direct) < address_rank(&relay));
        assert_eq!(
            route_label(&"/ip4/8.8.8.8/udp/443/quic-v1".parse().unwrap(), false),
            "DIRECT"
        );
    }

    #[test]
    fn wildcard_listener_addresses_are_not_advertised() {
        assert!(!is_advertisable_peer_address(
            &"/ip4/0.0.0.0/udp/443/quic-v1".parse().unwrap()
        ));
        assert!(!is_advertisable_peer_address(
            &"/ip6/::/udp/443/quic-v1".parse().unwrap()
        ));
        assert!(is_advertisable_peer_address(
            &"/ip4/127.0.0.1/udp/443/quic-v1".parse().unwrap()
        ));
    }

    #[test]
    fn relay_limits_apply_operator_bounds() {
        let limits = RelayLimits {
            max_reservations: 3,
            max_reservations_per_peer: 1,
            reservation_duration_secs: 17,
            max_circuits: 2,
            max_circuits_per_peer: 1,
            max_circuit_duration_secs: 19,
            max_circuit_bytes: 23,
            max_circuit_bandwidth_bytes_per_second: 29,
            max_total_bandwidth_bytes_per_second: 31,
            reservation_rate_per_peer: 1,
            reservation_rate_per_ip: 2,
            circuit_rate_per_peer: 3,
            circuit_rate_per_ip: 4,
            rate_interval_secs: 5,
        };
        let config = relay_limits(&limits).unwrap();
        assert_eq!(config.max_reservations, 3);
        assert_eq!(config.max_reservations_per_peer, 1);
        assert_eq!(config.reservation_duration, Duration::from_secs(17));
        assert_eq!(config.max_circuits, 2);
        assert_eq!(config.max_circuits_per_peer, 1);
        assert_eq!(config.max_circuit_duration, Duration::from_secs(19));
        assert_eq!(config.max_circuit_bytes, 23);
        assert_eq!(config.max_circuit_bytes_per_second, 29);
        assert_eq!(config.max_total_circuit_bytes_per_second, 31);

        let unbounded_bytes = RelayLimits {
            max_circuit_bytes: 0,
            ..limits
        };
        assert!(relay_limits(&unbounded_bytes).is_err());
    }

    #[tokio::test]
    async fn two_nodes_open_a_pinned_quic_stream() {
        let key_a = identity::Keypair::generate_ed25519();
        let key_b = identity::Keypair::generate_ed25519();
        let peer_b = key_b.public().to_peer_id();
        let (node_a, _incoming_a) = Node::start(key_a, loopback_options()).await.unwrap();
        let (node_b, mut incoming_b) = Node::start(key_b, loopback_options()).await.unwrap();

        let addresses = timeout(Duration::from_secs(5), async {
            loop {
                let listeners = node_b.snapshot().await.unwrap().listeners;
                if !listeners.is_empty() {
                    break listeners;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("node B did not publish a listener");

        let mut outbound = timeout(
            Duration::from_secs(10),
            node_a.open(peer_b, CONTROL_PROTOCOL, &addresses),
        )
        .await
        .expect("opening stream timed out")
        .expect("open pinned stream");
        let mut inbound = timeout(Duration::from_secs(10), incoming_b.recv())
            .await
            .expect("incoming stream timed out")
            .expect("incoming queue closed");

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
            NetworkOptions {
                relay_server: true,
                ..loopback_options()
            },
        )
        .await
        .unwrap();
        let relay_address =
            wait_for_listener(&relay, |address| !address.contains("p2p-circuit")).await;
        assert!(relay_address.ends_with(&format!("/p2p/{relay_peer}")));

        let key_b = identity::Keypair::generate_ed25519();
        let peer_b = key_b.public().to_peer_id();
        let (node_b, mut incoming_b) = Node::start_inner(
            key_b,
            NetworkOptions {
                relay_nodes: vec![relay_address.clone()],
                ..loopback_options()
            },
            false,
            false,
        )
        .await
        .unwrap();
        let relay_candidate =
            wait_for_listener(&node_b, |address| address.contains("p2p-circuit")).await;
        assert!(relay_candidate.ends_with(&format!("/p2p/{peer_b}")));

        let (node_a, _incoming_a) = Node::start_inner(
            identity::Keypair::generate_ed25519(),
            NetworkOptions {
                relay_nodes: vec![relay_address],
                ..loopback_options()
            },
            false,
            false,
        )
        .await
        .unwrap();
        // Wait until A has connected to the relay. Without this, the test races relay-client
        // transport setup and can report a canceled circuit request before networking begins.
        let _relay_candidate_a =
            wait_for_listener(&node_a, |address| address.contains("p2p-circuit")).await;
        let mut outbound = timeout(
            Duration::from_secs(15),
            node_a.open(peer_b, CONTROL_PROTOCOL, &[relay_candidate]),
        )
        .await
        .expect("opening relayed stream timed out")
        .expect("open relayed stream");
        let mut inbound = timeout(Duration::from_secs(15), incoming_b.recv())
            .await
            .expect("relayed inbound stream timed out")
            .expect("incoming queue closed");
        outbound.write_all(b"via-relay").await.unwrap();
        let mut received = [0u8; 9];
        inbound.stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"via-relay");
        wait_for_connection_path(&node_a, peer_b, "RELAYED").await;
        wait_for_connection_path(
            &node_b,
            node_a.snapshot().await.unwrap().peer_id.parse().unwrap(),
            "RELAYED",
        )
        .await;

        node_a.shutdown().await.unwrap();
        node_b.shutdown().await.unwrap();
        relay.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn relay_paces_opaque_circuit_bytes_at_the_configured_shared_rate() {
        let relay_key = identity::Keypair::generate_ed25519();
        let relay_peer = relay_key.public().to_peer_id();
        let (relay, _relay_incoming) = Node::start(
            relay_key,
            NetworkOptions {
                relay_server: true,
                relay_limits: RelayLimits {
                    max_circuit_bandwidth_bytes_per_second: 1_024,
                    max_total_bandwidth_bytes_per_second: 1_024,
                    ..RelayLimits::default()
                },
                ..loopback_options()
            },
        )
        .await
        .unwrap();
        let relay_address =
            wait_for_listener(&relay, |address| !address.contains("p2p-circuit")).await;
        assert!(relay_address.ends_with(&format!("/p2p/{relay_peer}")));

        let key_b = identity::Keypair::generate_ed25519();
        let peer_b = key_b.public().to_peer_id();
        let (node_b, mut incoming_b) = Node::start_inner(
            key_b,
            NetworkOptions {
                relay_nodes: vec![relay_address.clone()],
                ..loopback_options()
            },
            false,
            false,
        )
        .await
        .unwrap();
        let relay_candidate =
            wait_for_listener(&node_b, |address| address.contains("p2p-circuit")).await;

        let (node_a, _incoming_a) = Node::start_inner(
            identity::Keypair::generate_ed25519(),
            NetworkOptions {
                relay_nodes: vec![relay_address],
                ..loopback_options()
            },
            false,
            false,
        )
        .await
        .unwrap();
        wait_for_listener(&node_a, |address| address.contains("p2p-circuit")).await;
        let mut outbound = timeout(
            Duration::from_secs(15),
            node_a.open(peer_b, CONTROL_PROTOCOL, &[relay_candidate]),
        )
        .await
        .expect("opening paced relayed stream timed out")
        .expect("open paced relayed stream");
        let mut inbound = timeout(Duration::from_secs(15), incoming_b.recv())
            .await
            .expect("paced relayed inbound stream timed out")
            .expect("incoming queue closed");

        let payload = vec![42; 1_024];
        let started = Instant::now();
        outbound.write_all(&payload).await.unwrap();
        let mut received = vec![0; payload.len()];
        timeout(
            Duration::from_secs(5),
            inbound.stream.read_exact(&mut received),
        )
        .await
        .expect("paced relay transfer timed out")
        .unwrap();
        assert_eq!(received, payload);
        assert!(
            started.elapsed() >= Duration::from_millis(850),
            "a 1 KiB circuit transfer must not bypass the 1 KiB/s relay budget"
        );

        node_a.shutdown().await.unwrap();
        node_b.shutdown().await.unwrap();
        relay.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn saved_peer_reconnects_after_same_identity_restarts() {
        let key_a = identity::Keypair::generate_ed25519();
        let key_b = identity::Keypair::generate_ed25519();
        let peer_b = key_b.public().to_peer_id();
        let (node_a, _incoming_a) = Node::start(key_a, loopback_options()).await.unwrap();
        let (node_b, _incoming_b) = Node::start(key_b.clone(), loopback_options())
            .await
            .unwrap();
        let address = wait_for_listener(&node_b, |_| true).await;

        // `add_peer` is the in-memory representation of the persisted trusted peer record.
        // From here onward no caller starts another dial: the reconnect loop must use it.
        node_a
            .add_peer(peer_b, vec![address.clone()])
            .await
            .unwrap();
        wait_for_connection_path(&node_a, peer_b, "LAN").await;
        node_b.shutdown().await.unwrap();
        wait_for_disconnection(&node_a, peer_b).await;

        let listen = address
            .strip_suffix(&format!("/p2p/{peer_b}"))
            .unwrap()
            .to_owned();
        let (node_b, mut incoming_b) = restart_on_same_listener(&key_b, listen).await;
        wait_for_connection_path(&node_a, peer_b, "LAN").await;

        let mut outbound = timeout(
            Duration::from_secs(10),
            node_a.open(peer_b, CONTROL_PROTOCOL, &[]),
        )
        .await
        .expect("reconnected peer did not open a stream")
        .expect("open after automatic reconnect");
        let mut inbound = timeout(Duration::from_secs(10), incoming_b.recv())
            .await
            .expect("reconnected inbound stream timed out")
            .expect("incoming queue closed");
        outbound.write_all(b"reconnected").await.unwrap();
        let mut received = [0u8; 11];
        inbound.stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"reconnected");

        node_a.shutdown().await.unwrap();
        node_b.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn reconnect_disabled_does_not_redial_a_saved_peer() {
        let key_a = identity::Keypair::generate_ed25519();
        let key_b = identity::Keypair::generate_ed25519();
        let peer_b = key_b.public().to_peer_id();
        let (node_a, _incoming_a) = Node::start(
            key_a,
            NetworkOptions {
                reconnect: false,
                ..loopback_options()
            },
        )
        .await
        .unwrap();
        let (node_b, _incoming_b) = Node::start(key_b.clone(), loopback_options())
            .await
            .unwrap();
        let address = wait_for_listener(&node_b, |_| true).await;

        node_a
            .add_peer(peer_b, vec![address.clone()])
            .await
            .unwrap();
        wait_for_connection_path(&node_a, peer_b, "LAN").await;
        node_b.shutdown().await.unwrap();
        wait_for_disconnection(&node_a, peer_b).await;

        let listen = address
            .strip_suffix(&format!("/p2p/{peer_b}"))
            .unwrap()
            .to_owned();
        let (node_b, _incoming_b) = restart_on_same_listener(&key_b, listen).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            !node_a
                .snapshot()
                .await
                .unwrap()
                .connections
                .iter()
                .any(|connection| connection.peer_id == peer_b.to_string()),
            "reconnect=false must prevent automatic redial"
        );
        assert!(
            node_a
                .snapshot()
                .await
                .unwrap()
                .peers
                .iter()
                .any(|peer| peer.peer_id == peer_b.to_string() && peer.state == "DISCONNECTED")
        );

        node_a.shutdown().await.unwrap();
        node_b.shutdown().await.unwrap();
    }

    fn loopback_options() -> NetworkOptions {
        NetworkOptions {
            listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()],
            ..NetworkOptions::default()
        }
    }

    async fn restart_on_same_listener(
        key: &identity::Keypair,
        listen: String,
    ) -> (Node, mpsc::Receiver<Incoming>) {
        timeout(Duration::from_secs(10), async {
            loop {
                match Node::start(
                    key.clone(),
                    NetworkOptions {
                        listen: vec![listen.clone()],
                        ..NetworkOptions::default()
                    },
                )
                .await
                {
                    Ok(node) => return node,
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
        })
        .await
        .expect("same listener was not released after shutdown")
    }

    async fn wait_for_listener(node: &Node, predicate: impl Fn(&str) -> bool) -> String {
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(address) = node
                    .snapshot()
                    .await
                    .unwrap()
                    .listeners
                    .into_iter()
                    .find(|address| predicate(address))
                {
                    return address;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("listener was not published")
    }

    async fn wait_for_connection_path(node: &Node, peer: PeerId, expected: &str) {
        timeout(Duration::from_secs(15), async {
            loop {
                if node
                    .snapshot()
                    .await
                    .unwrap()
                    .connections
                    .iter()
                    .any(|connection| {
                        connection.peer_id == peer.to_string() && connection.path == expected
                    })
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("expected connection path was not established");
    }

    async fn wait_for_disconnection(node: &Node, peer: PeerId) {
        timeout(Duration::from_secs(10), async {
            loop {
                if !node
                    .snapshot()
                    .await
                    .unwrap()
                    .connections
                    .iter()
                    .any(|connection| connection.peer_id == peer.to_string())
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("peer did not disconnect after shutdown");
    }
}
