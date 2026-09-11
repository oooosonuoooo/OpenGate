# Networking

The network crate uses rust-libp2p 0.56 with Tokio, QUIC, TCP/Noise/Yamux, DNS, Identify, Ping, mDNS, AutoNAT, Circuit Relay v2 and DCUtR. It uses the upstream `libp2p-stream` 0.4.0-alpha stream API; that upstream component is explicitly prerelease and pinned through Cargo.lock. The CLI is independent of transport implementation.

Current primary API references: [SwarmBuilder](https://docs.rs/libp2p/0.56.0/libp2p/struct.SwarmBuilder.html), [stream control](https://docs.rs/libp2p-stream/0.4.0-alpha/libp2p_stream/), and [DCUtR](https://docs.rs/libp2p/0.56.0/libp2p/dcutr/index.html).

Addresses are libp2p multiaddresses, including the authenticated destination peer ID. Typical examples are `/ip4/192.0.2.10/udp/44344/quic-v1/p2p/PEER_ID` and `/ip6/2001:db8::10/tcp/44344/p2p/PEER_ID`. Documentation addresses are placeholders and must be replaced with reachable nodes.

The intended preference is LAN, public IPv6, public direct transport, hole punching, then relay. mDNS only supplies untrusted address hints. Remote Identify messages are not permission grants. Dial candidates are pinned to the selected peer ID.

No server can make all private networks directly reachable. Internet pairing needs reachable address hints or a shared configured relay. Configure one or more relay/bootstrap nodes in `config.toml`; a short token alone cannot discover an otherwise isolated peer.

The network loop retries saved peers with jittered 1, 2, 4, 8, 15, 30 and 60-second backoff, resetting after a stable connection. Ping monitors transport health. Wi-Fi interruption, sleep/wake and IP changes can still end a stream. A recovered transport authenticates the saved key again. File transfers can resume; existing TCP sessions and interactive commands are not replayed. Established libp2p streams belong to their existing connection, so a direct upgrade must not destroy an active relay stream.

Diagnostics report observed listeners, paths, peer IDs and ping latency. NAT or Internet states that have not been measured must remain unknown; a successful loopback test is not evidence of real CGNAT hole punching. See BUILD_STATUS for the actual test coverage.

`diagnose` performs bounded IPv4/IPv6 TCP reachability probes to Cloudflare's
documented DNS-over-TLS endpoints. No DNS query or device data is transmitted.
The result identifies the tested target; failure of that target does not prove
all Internet access is unavailable. When libp2p ping samples exist, diagnostics
show their observed failure percentage and label it as a ping estimate rather
than a raw packet-capture measurement; with no samples the value is unknown.

Connection status includes encryption, authenticated identity, local trust and
permissions granted to that peer, transport, observed path, agent version and
ping measurements. A discovered encrypted peer is not automatically trusted.
Compatible peers exchange application and protocol versions in their control
hello; incompatible framing reports the local and remote protocol numbers.

Use `opengate device preferences DEVICE --auto-reconnect false` to stop background
redialing that device while retaining trust and current streams. Explicit connects
still work. `--connection-timeout-seconds 5` bounds a future stream open; accepted
values are 5–30. Preferences survive database upgrades and restarts. Set
`--auto-reconnect true` to resume tracking. `config set bootstrap_nodes '["MULTIADDR"]'`
and `config set relay_nodes '["MULTIADDR"]'` require peer-pinned addresses and a daemon restart.

New streams prefer established direct QUIC, then direct TCP, then relayed
connections. Active streams keep their existing path so a direct upgrade cannot
replay a command or truncate a TCP session. See `vendor/README.md` for the small
upstream stream-selector patch.

`allow_network_targets` defaults to false: tunnels reach only the remote machine's loopback services. An owner can explicitly set it to true for arbitrary routed TCP destinations and SOCKS usage. Local proxies bind loopback unless the user passes `--acknowledge-public-bind` with a public listen address.

## Slow receivers and transfer flow control

QUIC advertises a 512 KiB receive window per stream and an 8 MiB connection
window. File receivers sync durable chunks before reading more; bounded windows
apply transport backpressure when disk writes lag behind the sender. They also
keep ordinary bursts below the QUIC implementation's fragment-count limit under
packet loss. They do not disable that limit or relax authentication. A single
stream's throughput on a high-latency path is consequently bounded by its receive
window divided by the round-trip time; parallel independent streams can share the
connection window.
