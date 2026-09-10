# Vendored libp2p DNS compatibility patches

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
