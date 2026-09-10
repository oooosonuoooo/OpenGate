# Self-hosted relay

OpenGate does not require a proprietary traffic service. On a machine with a publicly reachable address, run:

```console
opengate relay --listen /ip4/0.0.0.0/udp/44344/quic-v1 --listen /ip4/0.0.0.0/tcp/44344
```

Allow those selected ports through that relay machine's normal firewall. Port 443 may be used when available and authorized; do not replace another application's listener. The relay identity and address are visible in `opengate status --network` using the same state directory.

On each endpoint, configure the relay's real public multiaddress, including its peer ID:

```console
opengate config set relay_nodes '["/ip4/RELAY_IP/tcp/44344/p2p/RELAY_PEER_ID"]'
opengate service stop
opengate service start
```

Then generate a new pairing invitation. A relay reservation becomes a candidate address with `/p2p-circuit`. Both endpoints should use the same accessible relay for initial discovery. Multiple relay addresses may be configured.

Circuit Relay v2 transports the peer-to-peer encrypted connection. The relay sees endpoints, connection times, durations and byte volumes, but cannot decrypt the application streams. Configure and operate only infrastructure you own or are authorized to use.

The implementation bounds reservations, circuit duration, bytes per circuit, connection counts and reservation/circuit request rates. Per-circuit byte limits are total transfer quotas, not a throughput guarantee. Current aggregate bandwidth and operator configuration coverage is tracked in BUILD_STATUS; do not assume an unimplemented quota exists.

DCUtR attempts direct connectivity where the network permits. A relay can remain necessary on symmetric NAT, CGNAT or enterprise firewalls. Public relay deployment, availability and firewall maintenance belong to its owner.
