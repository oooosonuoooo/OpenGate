# Vendored libp2p compatibility and transport patches

OpenGate uses stable libp2p 0.56.0. Its released DNS and mDNS crates depend on
Hickory 0.25.2, which has no fix on that branch for RUSTSEC-2026-0118 and
RUSTSEC-2026-0119. These two crates retain their released libp2p dependencies
and use Hickory 0.26.1 or later (currently 0.26.2 in Cargo.lock).

- `libp2p-dns-0.44.0`: original crates.io 0.44.0 sources. The `src/lib.rs`
  compatibility changes come from upstream rust-libp2p's Hickory 0.26 migration:
  resolver construction, error type, typed-record iteration, and matching tests.
  The now-unused async-trait dependency is removed.
- `libp2p-mdns-0.48.0`: original crates.io 0.48.0 sources. The
  `src/behaviour/iface/query.rs` compatibility changes use the Hickory 0.26
  message/record fields. Its test-only identity dependency explicitly enables
  the `rand` feature, so the upstream tests also build in isolation. Discovery behavior and the stable libp2p APIs remain.

Upstream revision inspected: `164405ef77d80c0c5adf06e0a89b452bfe04bae8`.
Source: https://github.com/libp2p/rust-libp2p/tree/164405ef77d80c0c5adf06e0a89b452bfe04bae8
Both crates retain upstream MIT copyright and license notices in their sources.
`Cargo.toml.orig` records the original published manifests; the normalized
`Cargo.toml` is the effective patched manifest. The workspace patch table and
lockfile make the change reproducible without a live Git dependency.

Remove these overrides when a stable libp2p release incorporates patched
Hickory. Do not downgrade Hickory to 0.25 or suppress the advisories.

## Relay bandwidth pacing

`libp2p-relay-0.21.1` is an otherwise unmodified crates.io source snapshot with a small local
patch that adds bounded opaque-byte pacing to Circuit Relay v2. It exposes a per-circuit combined
direction rate and one aggregate rate shared by every circuit. The copy path retains its fixed-size
`BufReader` buffering, waits before a paced write, and leaves protocol negotiation and end-to-end
encryption untouched. OpenGate maps its positive `RelayLimits` rates to this patch; zero is
rejected by OpenGate rather than silently disabling its specified relay bound.
Each traffic direction has an independent pending write permit and shares the
circuit budget. The copy path also enforces the remaining byte quota before
every write and checks its lifetime even while traffic continuously progresses.

The patch is intentionally local because libp2p 0.56/relay 0.21.1 has admission, duration, and
total-byte quotas but no relay throughput pacing API. Remove the override when an upstream stable
release exposes equivalent per-circuit and aggregate pacing with bounded backpressure.

## Direct stream preference

`libp2p-stream-0.4.0-alpha` retains its published protocol and public API. Its
connection selector prefers an established direct connection, then direct QUIC,
instead of choosing randomly between relayed and direct paths. Existing streams
are left intact; new streams use the preferred path. Closed connections also
release their sender entry. The obsolete futures `try_next` call uses the current
equivalent `try_recv` API, with Futures 0.3.32 as its minimum. Tests exercise
direct selection and relay fallback.

The isolated upstream relay tests explicitly depend on `quickcheck`, which its
published manifest omitted despite using it in unit tests. This affects test
builds only. All vendored crates retain their original MIT license notices.

Upstream source snapshot SHA-256 (before workspace formatting):

- `dns.rs`: `5f6291a1c453fc7c38c3992b4beacaa48741d9b390485ef2ffce186f2e3d7ca7`
- `mdns-query.rs`: `f3003d2bf92df8141d2ab40502e57e8c53af94ff5b1c3782d9b26e7e6fcf01a7`

Advisories:
- https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3v94-mw7p-v465
- https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-q2qq-hmj6-3wpp

The audit also reports the unmaintained `paste` 1.0.15 macro used by
`netlink-packet-core` through libp2p's Linux interface watcher. This is a
maintenance warning, not a reported vulnerability in the audit. The macro
runs during compilation on checked-in dependency source; peer input does not
reach it. Keep the lockfile and audit gate, and replace it when the maintained
upstream netlink dependency provides that change. No advisory is ignored.
