# OpenGate requirements audit

**Scope and method.** This is a source-and-evidence audit of the current
working tree against all 78 sections in docs/SPECIFICATION.md. It distinguishes
implemented source, local automated evidence, cross-build evidence and physical
platform acceptance. The working tree is intentionally dirty and has not been
committed, pushed or published.

**Status key:** **Implemented** means the requirement is represented in current
source and has relevant local coverage where applicable. **Partial** means the
source is present but a material validation boundary or deliverable remains.
**Pending** means the required behavior has not been implemented or evidenced.
**Design-only** is deliberate future or optional scope, recorded separately from
a required-core gap.

The final evidence set is cargo fmt --check, locked workspace clippy, 42
passing locked workspace tests, cargo audit exit 0, the Linux release build,
a Windows x86_64 GNU release cross-build, final DEB/RPM/portable/ZIP/MSI
artifacts with SHA256SUMS, final TUI and Linux user-service checks, and the
isolated namespace network-loss tests. The final current-binary default network
run is in target/validation/network-interruption-final.log; the exact-tree 2 GiB + 17
byte acceptance is in target/validation/network-interruption-final-large.log. Physical Windows, reboot, restrictive
NAT/CGNAT and Linux-to-Windows acceptance are called out explicitly below.

## Remaining physical acceptance before a production claim

1. **Native Windows lifecycle and security (10, 15, 42, 44, 64, 65).** Run the
   MSI on Windows and verify UAC, SCM start/stop/recovery, LocalService and
   protected storage, ConPTY, upgrade/uninstall and bootstrap behavior.
2. **Linux-to-Windows workflows (72–73).** Pair real Linux and Windows hosts,
   exercise both terminal directions, Windows file resume and the RDP/VNC
   forwarding acceptance.
3. **Physical network/system interruption (6, 12–14, 27, 52, 74).** Verify
   restrictive NAT/CGNAT/DCUtR, interface changes, sleep/wake, machine reboot
   and Internet interruption on real hardware. The namespace harness is strong
   controlled Linux evidence but is not a substitute for those tests.
4. **Optional/future scope.** The integrated screen-capture/input GUI and
   automatic signed updater remain deliberately deferred and are documented in
   docs/UPDATE-DESIGN.md.

## Section matrix


| § | Status | Current evidence and remaining boundary |
|---|---|---|
| 1 | Implemented | The keyboard TUI presents Connect, Allow, Saved Devices, Connections, Settings and Diagnostics; the final PTY smoke asserted all six entries plus token display/regeneration/cancellation (crates/opengate-cli/src/tui.rs; target/validation/tui-smoke-final.log). |
| 2 | Partial | allow/connect creates and saves directional trust, and rename is exposed (crates/opengate-cli/src/main.rs; crates/opengate-cli/src/daemon.rs). Local and isolated-network pairing pass; a physical two-computer acceptance remains pending. |
| 3 | Implemented | The Device record persists identity, UUID, nickname, permissions, addresses, connection preferences, pairing/last-connected timestamps and trusted state. Migration v2 and preference validation/persistence tests cover existing schema v1 data (crates/opengate-core/src/lib.rs). The original token is never used as long-term authentication. |
| 4 | Partial | Persistent Ed25519/libp2p identity, UUID and protected storage exist (crates/opengate-security/src/lib.rs; windows_storage.rs). Linux permissions and key lifecycle are tested; DPAPI/Windows ACL behavior is source and cross-build evidence only. |
| 5 | Implemented | Tokio/libp2p QUIC and TCP/Noise/Yamux, Identify, AutoNAT, Circuit Relay v2, DCUtR, mDNS and Ping are configured (crates/opengate-network/src/lib.rs). Kademlia is conditional in the specification and is not needed for the configured bootstrap/relay model. |
| 6 | Partial | Address ranking, mDNS/direct/relay candidates, AutoNAT/DCUtR and user-run relays exist (crates/opengate-network/src/lib.rs; RELAY.md). Direct/forced-relay and isolated loss/restore tests pass, but restrictive-NAT/hole-punch and a physical route upgrade remain unverified. |
| 7 | Implemented | The networking stack is Rust/libp2p and the networking documentation records the direct-peer and self-hosted-relay model without a mandatory OpenGate cloud dependency (NETWORKING.md). |
| 8 | Implemented | Bounded versioned CBOR framing, request IDs, typed error replies and independent control/terminal/files/tunnel/desktop/clipboard protocols are implemented (crates/opengate-protocol/src/lib.rs). Health is provided by configured libp2p Ping and connection diagnostics. |
| 9 | Implemented | Per-device terminal/files/TCP/desktop/clipboard/full-admin permissions and presets are checked for every remote stream (crates/opengate-protocol/src/lib.rs; crates/opengate-cli/src/daemon.rs). |
| 10 | Partial | Windows service lifecycle, elevation checks, LocalService installation, recovery custom actions and MSI authoring are present (crates/opengate-service/src/lib.rs; packaging/windows/OpenGate.wxs). Native SCM/UAC/recovery/MSI install and uninstall remain unverified. |
| 11 | Partial | Secure generated systemd user/system units and elevated install paths exist (crates/opengate-service/src/lib.rs; packaging/linux/opengate.service). The generated user unit starts, restarts after SIGKILL with stable identity and stops cleanly; root/system installation still needs host validation. |
| 12 | Partial | Tracked peers expose DISCONNECTED, DIALING, CONNECTED and RECONNECTING states and use bounded jittered backoff (crates/opengate-network/src/lib.rs). The final namespace outage test proves reconnect on a Linux link loss; sleep, interface change, reboot and Windows behavior remain physical tests. |
| 13 | Partial | Ping runs every 10 seconds with a 30-second timeout and records successes/failures for diagnostics (crates/opengate-network/src/lib.rs). Controlled loss is exercised; interface-change and real Internet measurements are not. |
| 14 | Partial | Saved trust reconnects; file transfers retain durable offsets and terminal replay IDs prevent blind command replay (crates/opengate-files/src/lib.rs; crates/opengate-core/src/lib.rs). Existing tunnels and desktop streams are intentionally not replayed. |
| 15 | Partial | Native PTY supports resize, input and cancellation (crates/opengate-terminal/src/lib.rs) and Linux PTY tests pass. ConPTY is compiled and authored but requires a native Windows shell acceptance. |
| 16 | Implemented | Authorized loopback-default TCP forwarding provides conventional SSH-compatible forwarding (crates/opengate-cli/src/client.rs; crates/opengate-tunnel/src/lib.rs) and E2E covers the path. |
| 17 | Partial | Linux and Windows bootstrap scripts detect platform/tooling and offer explicit OpenSSH setup (scripts/bootstrap-linux.sh; scripts/bootstrap-windows.ps1). Linux checks pass; Windows execution is not available in this workspace. |
| 18 | Partial | Push/pull handle files and directories, progress, cancellation, overwrite, SHA-256 and durable resume (crates/opengate-cli/src/client.rs; crates/opengate-files/src/lib.rs). Final 128 MiB and 2 GiB+17-byte controlled network-outage tests pass; a Windows filesystem and physical Internet outage remain pending. |
| 19 | Implemented | Capability-rooted list/mkdir/rename/copy/delete/stat/upload/download/chmod APIs reject traversal, symlink escape, reserved paths and unsafe file roots (crates/opengate-protocol/src/lib.rs; crates/opengate-files/src/lib.rs). |
| 20 | Implemented | Multiple authorized TCP tunnel listeners and cancellation-aware bidirectional bridges exist (crates/opengate-cli/src/client.rs; crates/opengate-tunnel/src/lib.rs). |
| 21 | Implemented | SOCKS5 is supported and loopback-default; public bind requires explicit acknowledgement (crates/opengate-cli/src/main.rs; crates/opengate-tunnel/src/lib.rs). |
| 22 | Partial | RDP/VNC TCP tunneling, optional local-client launch and loopback defaults are implemented (crates/opengate-cli/src/client.rs). Native Windows RDP and a real client acceptance remain pending; integrated capture/input is documented optional future scope. |
| 23 | Partial | Explicit get/send/sync has an independent disabled-by-default permission and revocation path (crates/opengate-cli/src/clipboard.rs). A real desktop clipboard provider is not available in this headless Linux run. |
| 24 | Implemented | Devices/list/info/rename/permissions/revoke commands exist; revocation cancels active streams, removes tracking and disconnects (crates/opengate-cli/src/main.rs; crates/opengate-cli/src/daemon.rs). E2E covers the revoke and re-pair boundary. |
| 25 | Partial | SQLite stores devices, pairing tokens, replay requests and audit events; TOML stores configuration and filesystem checkpoints store transfer state (crates/opengate-core/src/lib.rs). Separate session/relay/transfer tables are not required for the current durable design but remain a schema extension if operational history needs them. |
| 26 | Partial | New stream selection ranks LAN/direct/IPv6/hole-punched paths over relay, prefers QUIC, then uses ping loss and latency (crates/opengate-network/src/lib.rs). Existing streams are deliberately not migrated; a physical relay-to-direct upgrade remains unverified. |
| 27 | Partial | mDNS and scan are implemented and discovery never grants trust (crates/opengate-network/src/lib.rs; crates/opengate-cli/src/main.rs). No physical LAN discovery run is available here. |
| 28 | Partial | Configurable connection/stream limits, task isolation, per-stream direction limits and relay admission/pacing limits exist (crates/opengate-core/src/lib.rs; crates/opengate-network/src/lib.rs). A multi-peer failure-isolation acceptance is not separately recorded. |
| 29 | Implemented | SQLite audit events redact sensitive details, logs is exposed and tracing is initialized (crates/opengate-core/src/lib.rs; crates/opengate-cli/src/main.rs). Verbosity remains controlled through RUST_LOG. |
| 30 | Partial | diagnose reports local/remote app and protocol versions, authentication, IPv4/IPv6 TCP probes, path explanation, encrypted/authenticated transport fields and a ping-derived loss estimate (crates/opengate-cli/src/diagnostics.rs; crates/opengate-network/src/lib.rs). Probes intentionally describe only their stated resolver and are not Internet-wide or raw packet-capture proof. |
| 31 | Partial | Mutual authentication, encrypted libp2p transport, protected secrets, rate/size/connection limits, secure paths and revocation are implemented (SECURITY.md; crates/opengate-cli/src/daemon.rs). OS-specific and hostile-network validation remains incomplete. |
| 32 | Implemented | Random 256-bit one-time expiring secrets, peer-pinned hints, stored hashes, transactional consumption and identity exchange are implemented (crates/opengate-security/src/lib.rs; crates/opengate-core/src/lib.rs). |
| 33 | Implemented | Token TTL is bounded to 60–900 seconds, one-use, cancelable and hash-only in storage (crates/opengate-cli/src/daemon.rs; crates/opengate-core/src/lib.rs). |
| 34 | Partial | Full-admin requires owner configuration, explicit per-peer grant and visible acknowledgement (crates/opengate-cli/src/main.rs; crates/opengate-cli/src/daemon.rs). It never bypasses UAC/sudo, and privileged Windows service behavior needs native validation. |
| 35 | Implemented | Local device trust requires no cloud account and the crate boundaries leave account/role features optional (README.md; docs/ARCHITECTURE.md). |
| 36 | Implemented | Clap exposes the command family for pairing, devices, shell, files, forwarding, service, relay, logs, config, update and version (crates/opengate-cli/src/main.rs). Unsigned update delivery refuses safely. |
| 37 | Implemented | No-argument launch opens the Ratatui keyboard TUI with the specified principal actions and device actions (crates/opengate-cli/src/tui.rs). |
| 38 | Implemented | Networking is isolated in reusable crates and the TUI uses the authenticated daemon API (docs/ARCHITECTURE.md). The optional GUI is deliberately future scope. |
| 39 | Implemented | Cargo workspace, named crates, scripts, packaging, documentation and workflows are present (Cargo.toml; repository layout). |
| 40 | Implemented | Maintained Rust dependencies are locked, cargo audit is wired and the final audit exits 0 with the documented unmaintained transitive paste warning (.github/workflows/ci.yml; vendor/README.md; target/validation/audit-final.log). |
| 41 | Implemented | Linux bootstrap detects distribution/architecture/Rust, previews changes, supports opt-in system modifications and runs build/test steps (scripts/bootstrap-linux.sh). |
| 42 | Partial | Windows bootstrap detects architecture/Rust/build tooling and offers opt-in OpenSSH setup (scripts/bootstrap-windows.ps1). It requires a native Windows execution for final evidence. |
| 43 | Implemented | End-user packages contain compiled binaries: final DEB/RPM/portable Linux archives, Windows ZIP and MSI were rebuilt and checksummed (scripts/package-linux.sh; target/packages/SHA256SUMS). Users do not need Rust or Cargo. |
| 44 | Partial | WiX source and the final locally built MSI install the binary, service, LocalService identity, automatic start, recovery actions and protected data directory (packaging/windows/OpenGate.wxs; MSI table/extraction evidence). Native install/upgrade/uninstall still needs Windows. |
| 45 | Implemented | DEB, RPM and portable Linux packaging plus systemd unit are implemented and final current-tree artifacts pass metadata/archive/hash checks (scripts/package-linux.sh; target/packages/). |
| 46 | Implemented | The specified initial Windows x86_64 and Linux x86_64 targets have release binaries and labeled artifacts. ARM64 is a later practical target in the specification, not part of the initial gate. |
| 47 | Implemented | CI and release workflows run fmt, clippy, tests, builds, audit and packages on Ubuntu/Fedora/Windows, use Cargo download caching, and avoid signing secrets (.github/workflows/ci.yml; .github/workflows/release.yml). No hosted run is claimed because this checkout has no origin. |
| 48 | Implemented | Stable typed error codes, retryability and domain preservation now cross control/file/service/tunnel/network reply boundaries while legacy messages are classified at the edge (crates/opengate-protocol/src/lib.rs; affected crate clients). |
| 49 | Partial | Workspace tests cover identity, token, pairing, trust, replay, revocation, framing, forwarding, files, reconnect, relay, services and migrations (target/validation/workspace-tests-final.log). Physical platform and adversarial Internet scenarios remain outside this Linux run. |
| 50 | Implemented | The unprivileged scripts/test-network-interruption.py harness creates two user/network namespaces, routed veth subnets, delay/loss, outage/restore and cleanup. The final default and large runs passed (docs/NETWORK-TESTS.md; target/validation/network-interruption-final.log). |
| 51 | Implemented | The final harness automatically detected a real link outage, preserved a durable checkpoint, reconnected a saved peer without a new invitation and resumed the CLI transfer to a matching SHA-256. |
| 52 | Partial | A generated Linux user service starts, restarts after SIGKILL with stable identity and stops cleanly (scripts/test-linux-service.py; target/validation/linux-service-final.log). This is crash recovery, not an operating-system reboot; native Windows startup/reboot is unverified. |
| 53 | Partial | Tests cover expiry/reuse, malformed/oversized frames, unknown/revoked trust, permission/path escape, cancellation, replay and rapid concurrent token consumption. A complete packet-mutation and physical adversarial matrix is still pending. |
| 54 | Implemented | Independent libp2p streams, Tokio I/O, bounded framing, QUIC receive windows, per-stream pacing and durable file backpressure are implemented and tested (crates/opengate-network/src/lib.rs; NETWORKING.md). |
| 55 | Implemented | status --network reports per-peer bytes/active streams and sampled rates; stream/direction limits and relay aggregate/per-circuit pacing use bounded buffers and hard quotas (crates/opengate-cli/src/traffic.rs; crates/opengate-network/src/lib.rs; RELAY.md). |
| 56 | Implemented | Private TOML config validates listen/reconnect/pairing/relay/limits and never stores the private key; config set supports bootstrap and relay nodes and security-policy changes cancel active streams (crates/opengate-core/src/lib.rs; crates/opengate-cli/src/daemon.rs). |
| 57 | Implemented | The same binary can serve Circuit Relay v2 with reservation/circuit/duration/byte/admission limits, per-circuit pacing and an aggregate bandwidth budget. Vendored relay tests and a three-node transfer pass (crates/opengate-network/src/lib.rs; vendor/libp2p-relay-0.21.1; RELAY.md). |
| 58 | Implemented | Bootstrap/relay nodes are validated multiaddrs, configurable through the daemon API, and pairing tokens carry peer/address hints (crates/opengate-core/src/lib.rs; crates/opengate-cli/src/daemon.rs; crates/opengate-security/src/lib.rs). |
| 59 | Implemented | Self-hosted relay operation and the restrictive-network limitation are documented (RELAY.md; NETWORKING.md). |
| 60 | Implemented | Device info and network status render path, transport, encrypted/authenticated state, remote agent version, latency, ping successes/failures, trusted state and granted permissions (crates/opengate-cli/src/main.rs; crates/opengate-network/src/lib.rs). |
| 61 | Design-only | Signed-update trust, key rotation, rollback and migration are documented and unsigned execution is refused (docs/UPDATE-DESIGN.md; crates/opengate-cli/src/main.rs). A working signed updater is deliberately future release scope. |
| 62 | Implemented | Control hello exchanges application and protocol versions and rejects incompatible protocol versions with an upgrade explanation (crates/opengate-protocol/src/lib.rs; crates/opengate-cli/src/daemon.rs; crates/opengate-cli/src/diagnostics.rs). |
| 63 | Implemented | Transactional numbered SQLite migration rejects a newer schema and migration v2 preserves trusted devices while adding connection preferences (crates/opengate-core/src/lib.rs; migration tests). |
| 64 | Partial | Atomic config/state writes, durable checkpoints, Linux restart policy and Windows service recovery source exist. Native Windows recovery and system-service paths need physical proof. |
| 65 | Partial | SIGTERM/Ctrl-C shutdown, cancellation tokens and node shutdown are implemented. Windows service-stop source exists but requires native runtime validation. |
| 66 | Implemented | README and networking documentation limit reconnect claims to viable paths, distinguish durable file resume from non-replayable streams and state physical test boundaries (README.md; NETWORKING.md; docs/NETWORK-TESTS.md). |
| 67 | Implemented | SECURITY explains that full admin is owner-configured privilege and never a UAC/sudo bypass (SECURITY.md). |
| 68 | Implemented | README, install, networking, security, pairing, relay, troubleshooting, development and network-test documents provide user and operator instructions. |
| 69 | Implemented | SECURITY covers identities, tokens, encrypted transport, permissions, storage, revocation, relay privacy, limitations and reporting (SECURITY.md). |
| 70 | Implemented | The modular workspace passes final formatter, clippy, workspace tests and audit gates; unsafe blocks and release credentials are controlled (target/validation/*-final.*; vendor/README.md). |
| 71 | Partial | Phases 1–9 and the release artifact stage are implemented locally. Native Windows, physical cross-platform and Internet/NAT/reboot acceptance in phase 10 remain open (BUILD_STATUS.md). |
| 72 | Pending | The required Linux↔Windows pair, Linux terminal after a real reboot and reverse Windows ConPTY workflow have not been physically performed in this Linux workspace. |
| 73 | Pending | No real Linux-to-Windows RDP forwarding/client acceptance evidence is available. |
| 74 | Partial | The final 2 GiB+17-byte transfer and exact-tree 128 MiB run survive a real controlled Linux link outage, reconnect automatically and match SHA-256 (docs/NETWORK-TESTS.md; target/validation/network-interruption-final.log; target/validation/network-interruption-final-large.log). The specification's physical Internet interruption remains unproven. |
| 75 | Implemented | Revocation prevents reauthentication and cancels active streams; the CLI E2E covers rejection and fresh pairing (crates/opengate-cli/tests/e2e.rs; target/validation/workspace-tests-final.log). |
| 76 | Partial | Complete source, services, networking, CLI/TUI, tests, scripts, workflows, final x86_64 packages, MSI tables and documentation exist. Native MSI/SCM/UAC and cross-platform acceptance are the explicit §76 exception requiring physical Windows/Linux validation. |
| 77 | Partial | BUILD_STATUS.md records completed work, validation, pending physical tests and future scope; source favors working modules over pseudocode. Hosted-agent provenance and official-API review are not claims made by repository evidence. |
| 78 | Partial | Pair-once/trusted/reconnect/relay design is implemented and documented (README.md; docs/ARCHITECTURE.md). The promised cross-platform automatic availability experience awaits the physical acceptance in §§72–74. |

## Evidence limits and release decision

The current local evidence supports the implemented Linux behavior, direct and
relay paths, durable transfer recovery under a real controlled link outage,
typed error contracts, diagnostics, release packages and cross-built Windows
artifacts. It does not support a claim that native Windows runtime, MSI
installation on Windows, UAC/SCM behavior, Linux-to-Windows terminal/RDP,
machine reboot, sleep/interface recovery or restrictive Internet NAT/CGNAT
traversal has passed. Those boundaries are intentional and are the exact
platform-specific validation still required by §76.
