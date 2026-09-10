# OpenGate requirements audit

**Scope and method.** This is a read-only source-and-evidence audit of the current
working tree against the 78 numbered sections in `docs/SPECIFICATION.md`.  It
does not treat an implementation, a unit test, a cross-build, or a design
document as equivalent to a physical cross-platform acceptance test.  The
working tree is dirty; no provenance or release claim is made here.  References
use `path:line` locations in the audited tree.

**Status key:** **Implemented** means the requirement is represented in current
source and has relevant local coverage where applicable. **Partial** means a
material part, validation boundary, or required deliverable is still missing.
**Pending** means no adequate implementation/evidence was found. **Design-only**
is deliberate future/optional scope, recorded separately from a required-core
gap. Validation evidence is limited to the latest recorded logs under
`target/validation/`: workspace tests (39 passed, one large test ignored in
the normal run), clippy and audit; the separately run 2 GiB+17-byte transfer;
Linux user-service crash/restart; and a Windows x64 GNU cross-build.

## Priority work before a production claim

1. **Required cross-platform acceptance remains unproven (72–74).** There is
   no real Linux-to-Windows pairing, reverse ConPTY shell, Windows RDP tunnel,
   real reboot, or Internet/NAT-interruption test. The current large-file test
   proves host-*process* interruption at 1 GiB and SHA-256 resume, not a network
   outage (`target/validation/large-transfer.log`; `BUILD_STATUS.md:20-30`).
2. **The trusted-device record omits connection preferences (3).** `Device` and
   the SQLite `devices` schema persist identity, permissions, addresses and
   timestamps but no connection-preference field
   (`crates/opengate-core/src/lib.rs:144-156,425-451`). Add a migration and a
   UI/CLI policy surface before calling §3 complete.
3. **Relay limits are incomplete (57).** Circuit/session, duration, byte quota,
   and admission limits are present, but current source explicitly says it does
   not enforce relay aggregate or per-connection throughput rate
   (`crates/opengate-network/src/lib.rs:82-99`; `RELAY.md:29-30`). This is an
   implementation gap until the pending relay pacing work lands and is tested.
4. **Release installers are not final artifacts (43–45, 76).** Linux DEB/RPM
   and portable packages were built before the latest changes and need rebuilding.
   Windows MSI source exists, but WiX construction requires Windows; the Linux
   attempt recorded a platform warning and directory errors before the present
   source revision (`target/validation/windows-msi.log`). Physical MSI/SCM/UAC
   install/uninstall remains unverified.
5. **Diagnostics and version negotiation do not yet meet their complete display
   contracts (30, 60, 62).** The current snapshot reports listeners, peer/path,
   NAT state and ping latency, but not measured Internet/IPv6 availability,
   packet loss, full per-connection authorization display, or remote application
   version. Framing rejects mismatched protocol version correctly, but no
   peer-version exchange produces the requested local/remote compatibility
   explanation (`crates/opengate-network/src/lib.rs:155-186`; 
   `crates/opengate-protocol/src/lib.rs:47-75`).
6. **Release gates must be run against the final tree (76).** The current
   recorded full test/clippy/audit evidence predates noted receive-window/retry
   and CLI-input changes (`BUILD_STATUS.md:33-50`). Do not promote based on the
   older log set alone.

## Section matrix

| § | Status | Current evidence and remaining boundary |
|---|---|---|
| 1 | Partial | Keyboard TUI presents Connect, Allow, Saved Devices, Connections, Settings and Diagnostics; Allow view copies/regenerates/cancels a token (`crates/opengate-cli/src/tui.rs:21-85,104-140`). It is a CLI TUI, not a graphical main interface; final UI verification remains. |
| 2 | Partial | `allow`/`connect` pair and save directional trust; rename is exposed (`crates/opengate-cli/src/main.rs:471-565`; `crates/opengate-cli/src/daemon.rs:578-626`). Local daemon E2E passes, but real two-computer pairing is pending. |
| 3 | Partial | Persistent public key, UUID, nickname, permissions, addresses, pairing/last-connected and trusted state are stored (`crates/opengate-core/src/lib.rs:144-156,425-451`). **Connection preferences are absent**; original token is not persisted. |
| 4 | Partial | Persistent Ed25519/libp2p key, UUID and protected storage exist (`crates/opengate-security/src/lib.rs:43-81`; `windows_storage.rs`). Linux permissions are tested; DPAPI/Windows ACL path is source/cross-build only. |
| 5 | Implemented | Tokio/libp2p QUIC and TCP/Noise/Yamux, Identify, AutoNAT, relay v2, DCUtR, mDNS and Ping are configured (`crates/opengate-network/src/lib.rs:198-281`). Kademlia is not included; the specification makes it conditional. |
| 6 | Partial | Address ranking, mDNS/direct/relay candidates, AutoNAT/DCUtR and user-run relays exist (`crates/opengate-network/src/lib.rs:672-728,1071-1124`; `RELAY.md`). Forced relay and loopback direct tests pass, but no restrictive-NAT/hole-punch or real route-upgrade evidence exists. |
| 7 | Implemented | The Rust networking stack is libp2p and documentation expressly rejects WhatsApp dependency (`NETWORKING.md:1-17`). |
| 8 | Partial | Versioned bounded CBOR framing, request IDs, error replies and six service protocols are implemented (`crates/opengate-protocol/src/lib.rs:8-75,223-289`). The requested heartbeat protocol is registered (`opengate-network/src/lib.rs:42-62`), while health is implemented through libp2p Ping rather than application heartbeat frames. |
| 9 | Implemented | Per-device terminal/files/TCP/desktop/clipboard/full-admin permissions and presets are enforced for each stream (`crates/opengate-protocol/src/lib.rs:78-114`; `crates/opengate-cli/src/daemon.rs:363-493`). |
| 10 | Partial | Windows service lifecycle, elevation checks and MSI service authoring are present (`crates/opengate-service/src/lib.rs:248-400,435-500`; `packaging/windows/OpenGate.wxs`). No physical Windows SCM/UAC/recovery/MSI test yet. |
| 11 | Partial | Secure generated systemd user/system units and elevated system install paths exist (`crates/opengate-service/src/lib.rs:272-431`; `packaging/linux/opengate.service`). Real user-service crash restart passed; system/root install still needs physical validation. |
| 12 | Partial | Tracked peers retry with jittered 1/2/4/8/15/30/60-second backoff (`crates/opengate-network/src/lib.rs:58-61,602-728`). The exposed state set is narrower than the requested state machine, and network/sleep/reboot scenarios remain untested. |
| 13 | Partial | Ping is configured at 10 seconds with 30-second timeout (`crates/opengate-network/src/lib.rs:258-263`). Its real loss/interface-change behaviour has not been measured. |
| 14 | Partial | Saved trust reconnects; transfers retain durable offsets; terminal replay IDs prevent blind command replay (`crates/opengate-files/src/lib.rs:655-736`; `crates/opengate-core/src/lib.rs:334-349`). Existing tunnels/desktop streams do not automatically reopen, by design. |
| 15 | Partial | Native PTY terminal supports resize, input and cancellation (`crates/opengate-terminal/src/lib.rs:25-177`), with Linux PTY tests. ConPTY is compiled but needs physical Windows validation. |
| 16 | Implemented | Authorized loopback-default TCP forwarding provides conventional SSH compatibility (`crates/opengate-cli/src/client.rs:439-561`; `crates/opengate-tunnel/src/lib.rs:19-95`); E2E covers forwarding. |
| 17 | Partial | Linux and Windows bootstrap scripts detect OpenSSH and only install when explicitly requested (`scripts/bootstrap-linux.sh:9-32,70`; `scripts/bootstrap-windows.ps1:31-68`). This is developer/bootstrap flow, not a finished end-user installer prompt, and Windows execution is unverified. |
| 18 | Partial | Push/pull handle directories, progress, cancellation, overwrite, SHA-256 and durable resume (`crates/opengate-cli/src/client.rs:155-410`; `crates/opengate-files/src/lib.rs:100-376`). 2 GiB+17-byte process-interruption resume passed; Internet outage and Windows local-resume behaviour are pending. |
| 19 | Implemented | Capability-rooted list/mkdir/rename/copy/delete/stat/upload/download/chmod API rejects traversal and symlink escape (`crates/opengate-protocol/src/lib.rs:156-222`; `crates/opengate-files/src/lib.rs:468-579`). POSIX modes are correctly unsupported on non-POSIX platforms. |
| 20 | Implemented | Multiple authorized TCP tunnel listeners and cancellation-aware bidirectional bridges exist (`crates/opengate-cli/src/client.rs:448-507`; `crates/opengate-tunnel/src/lib.rs:45-73`). |
| 21 | Implemented | SOCKS5 is supported and loopback-default; public bind requires explicit acknowledgement (`crates/opengate-cli/src/main.rs:590-610`; `client.rs:426-507`; `opengate-tunnel/src/lib.rs:114-193`). |
| 22 | Partial | RDP/VNC TCP tunnel, optional local-client launch and loopback default are implemented (`crates/opengate-cli/src/client.rs:448-561`). A real Windows RDP acceptance test and Linux client validation are pending. Integrated capture/input desktop is an **optional future design**, not a missing MVP core module. |
| 23 | Partial | Explicit get/send/sync has an independent disabled-by-default permission and revocation path (`crates/opengate-cli/src/clipboard.rs`; `crates/opengate-protocol/src/lib.rs:78-114`). Interactive desktop-provider operation remains unverified. |
| 24 | Implemented | Devices table/list/info/rename/permissions/revoke commands exist; revoke cancels active streams and disconnects (`crates/opengate-cli/src/main.rs:164-217,540-588`; `daemon.rs:640-654`). E2E covers revocation. |
| 25 | Partial | SQLite has devices, pairing tokens, replay requests, audit log and numbered migrations (`crates/opengate-core/src/lib.rs:159-451`). Settings live in TOML and transfers on filesystem; separate suggested sessions/relay/transfers tables are not present. |
| 26 | Partial | Direct addresses rank above relay and paths are labeled (`crates/opengate-network/src/lib.rs:672-728,1071-1124`). There is no latency/reliability optimizer or externally verified safe migration from an active relayed session. |
| 27 | Partial | mDNS and `scan` are implemented; discovery never grants trust (`crates/opengate-network/src/lib.rs:258-281`; `crates/opengate-cli/src/main.rs:626-633`). No physical LAN discovery evidence. |
| 28 | Partial | Configurable connection/stream limits, task isolation and relay limits exist (`crates/opengate-core/src/lib.rs:19-62`; `daemon.rs:32-46`). Multiple-peer failure isolation is not separately demonstrated. |
| 29 | Implemented | SQLite audit events redact sensitive details, `logs` is exposed, and tracing is initialized (`crates/opengate-core/src/lib.rs:351-382,532-559`; `crates/opengate-cli/src/main.rs:420-430`). Verbosity is controlled through standard `RUST_LOG`. |
| 30 | Partial | `diagnose` and status return authentication result, listeners, paths, NAT status and ping latency (`crates/opengate-cli/src/main.rs:616-625`; `opengate-network/src/lib.rs:155-186`). No measured Internet/IPv6, packet loss, direct/hole-punch verdict, or clear relay fallback narrative. |
| 31 | Partial | Mutual authentication, encrypted libp2p transport, secret storage, rate/size/connection limits and secure paths are present (`SECURITY.md`; `crates/opengate-cli/src/daemon.rs:363-493`). OS-specific and hostile-network validation is incomplete. |
| 32 | Implemented | Random 256-bit one-time expiring secret, peer-pinned token, stored hash, transactional consumption and identity exchange are implemented (`crates/opengate-security/src/lib.rs:88-212`; `crates/opengate-core/src/lib.rs:280-327`). |
| 33 | Implemented | Token TTL is bounded to 60–900 seconds, is one-use, cancelable, and only its hash is stored (`crates/opengate-cli/src/daemon.rs:563-577`; `crates/opengate-core/src/lib.rs:280-333`). |
| 34 | Partial | Full-admin requires owner config plus explicit per-peer grant and visible acknowledgement (`crates/opengate-cli/src/main.rs:250-259`; `daemon.rs:471-493`). Privileged Windows service operation needs physical validation. |
| 35 | Implemented | Local device trust needs no cloud account and clean crate boundaries leave future account/role work possible (`README.md:1-10`; `docs/ARCHITECTURE.md:15-23`). Multi-user/organization features are intentionally future scope. |
| 36 | Implemented | Clap exposes the requested command family, including service/relay/pairing/log/config/update/version (`crates/opengate-cli/src/main.rs:17-243`). `update` safely refuses unsigned delivery. |
| 37 | Implemented | No-argument command opens the Ratatui keyboard TUI with the specified principal actions and device actions (`crates/opengate-cli/src/tui.rs:104-257`). |
| 38 | Implemented | Networking is isolated in reusable crates and the TUI uses the daemon API (`docs/ARCHITECTURE.md:15-23`). GUI is an **optional future design**, not a core delivery blocker. |
| 39 | Implemented | Cargo workspace, named crates, scripts, packaging, docs and workflows are present (`Cargo.toml`; repository layout). |
| 40 | Partial | Maintained Rust dependencies and `cargo audit` are wired (`Cargo.toml`; `.github/workflows/ci.yml:1-41`). Latest audit exits 0 with one documented unmaintained transitive `paste` warning (`target/validation/audit.log`). |
| 41 | Implemented | Linux bootstrap detects distro/architecture/Rust, previews changes, supports opt-in application and builds/tests (`scripts/bootstrap-linux.sh`). |
| 42 | Partial | Windows bootstrap detects architecture/Rust/build tooling and offers opt-in OpenSSH (`scripts/bootstrap-windows.ps1`). It has no physical Windows execution evidence or proven installer production. |
| 43 | Partial | Packages contain compiled binary (`scripts/package-linux.sh:1-83`); Windows release EXE cross-build passed. Final current-revision DEB/RPM/portable and MSI artifacts remain pending. |
| 44 | Partial | WiX source installs binary/service/ACL-protected state, auto-start and uninstall controls (`packaging/windows/OpenGate.wxs`). MSI must be constructed and installed on Windows. |
| 45 | Partial | DEB/RPM/portable package logic and systemd unit are implemented (`scripts/package-linux.sh`; `packaging/debian`; `packaging/rpm`). Existing Linux artifacts need rebuild after latest changes. |
| 46 | Partial | Linux x86_64 artifacts and Windows x86_64 GNU cross-build are evidenced. ARM64 is future practical scope and no ARM artifact is recorded. |
| 47 | Partial | CI runs fmt/clippy/test/build/audit/package on Ubuntu, Fedora and Windows; release workflow builds packages (`.github/workflows/ci.yml`; `release.yml`). No cache steps are present, and no successful hosted workflow evidence is recorded. |
| 48 | Partial | Production paths use contextual `anyhow` errors and bounded timeouts, with understandable common errors (`crates/opengate-cli/src/client.rs`; `daemon.rs`). The requested typed error taxonomy is not implemented. |
| 49 | Partial | Unit/E2E coverage includes identity, token, pairing, trust, replay, revocation, framing, forwarding, files, reconnect, services and migrations (`target/validation/workspace-tests.log`). Network-loss, physical platform and some adversarial scenarios are still absent. |
| 50 | Pending | No container/network-namespace or packet-loss/latency simulation harness was found. In-process loopback covers direct/relay/restart only. |
| 51 | Partial | Saved-peer automatic reconnect after same-identity process restart is tested (`crates/opengate-network/src/lib.rs:1322-1368`). No automated network-drop/restore test. |
| 52 | Partial | Linux user-service forced crash restart with stable identity passed (`target/validation/linux-service.log`). That is not an OS reboot; Windows startup/reboot is unverified. |
| 53 | Partial | Tests cover expiry/reuse, malformed/oversized frames, unknown/revoked trust, permission and file escape; pairing attempts have a runtime limit (`crates/opengate-cli/src/daemon.rs:382-407`). A complete security-test matrix, including packet mutation and rapid-attempt evidence, is not recorded. |
| 54 | Implemented | Independent libp2p streams, Tokio I/O, bounded framing, receive windows and durable file backpressure are implemented (`crates/opengate-network/src/lib.rs:218-235`; `NETWORKING.md:20-31`). |
| 55 | Partial | `status --network` reports per-peer bytes/active streams and configured per-stream direction pacing (`crates/opengate-cli/src/traffic.rs`; `daemon.rs:181-198,554`). Measured upload/download throughput is sampled only on demand; relay aggregate pacing remains missing. |
| 56 | Partial | Private TOML config contains listen, reconnect, pairing, relay, limits and no private key (`crates/opengate-core/src/lib.rs:19-142`). Runtime `config set` cannot set `bootstrap_nodes`, and the example section layout is not used. |
| 57 | Partial | Same binary runs relay; Circuit Relay v2 limits reservations, circuits, duration, bytes and request rates (`crates/opengate-network/src/lib.rs:82-153,960-991`). Aggregate bandwidth and per-connection rate enforcement are missing. |
| 58 | Partial | Config has bootstrap/relay nodes and tokens carry peer/address hints (`crates/opengate-core/src/lib.rs:19-62`; `crates/opengate-security/src/lib.rs:88-163`). Bootstrap values are not exposed through `config set`; relay hints depend on learned candidates. |
| 59 | Implemented | Self-hosted relay configuration and the restrictive-network limitation are documented (`RELAY.md`; `NETWORKING.md:12-17`). |
| 60 | Partial | Device/status output shows peer, observed path, latency and permissions (`crates/opengate-cli/src/main.rs:336-418`; `daemon.rs:554`). It does not consistently render all requested encrypted/authenticated/transport/permission fields in one user-facing connection display. |
| 61 | Design-only | Signed-update trust, rotation and rollback contract is documented; executable updates are safely disabled without a signing key (`docs/UPDATE-DESIGN.md`; `crates/opengate-cli/src/main.rs:706-709`). A working signed updater is deliberately future release scope. |
| 62 | Partial | Wire protocol has strict version negotiation/rejection (`crates/opengate-protocol/src/lib.rs:8-75`). No exchanged OpenGate application version or user-facing local-versus-remote version report. |
| 63 | Implemented | Transactional numbered SQLite migration rejects a newer schema and preserves trust (`crates/opengate-core/src/lib.rs:425-451`; tests at `:644-652`). |
| 64 | Partial | Atomic config/state writes, checkpoint resume, Linux restart policy and Windows service recovery source exist (`crates/opengate-core/src/lib.rs:64-115`; `opengate-service/src/lib.rs`). Windows recovery and system-service paths need physical proof. |
| 65 | Partial | SIGTERM/Ctrl-C daemon shutdown, cancellation tokens and node shutdown are implemented (`crates/opengate-cli/src/daemon.rs:131-168,211-218`). Windows service-stop source exists but needs runtime validation. |
| 66 | Implemented | README/NETWORKING explicitly limit reconnect claims to viable paths and acknowledge physical interruption (`README.md:57-66`; `NETWORKING.md:12-17`). |
| 67 | Implemented | SECURITY explains that full admin is owner-configured privilege, never UAC/sudo bypass (`SECURITY.md:22-31`). |
| 68 | Implemented | Required README, install, networking, security, pairing, relay, troubleshooting and development documents exist with pairing instructions. |
| 69 | Implemented | SECURITY covers identities, tokens, encryption, permissions, storage, revocation, relay privacy, limitations and reporting (`SECURITY.md`). |
| 70 | Partial | Modular crates, fmt/clippy/tests, documented unsafe blocks and no embedded credentials are evident. Final fmt/clippy/test/audit must be repeated after the latest changes. |
| 71 | Partial | Phases 1–9 have substantial implementation; phase 10 final installers/artifacts/security completion remains open (`BUILD_STATUS.md`). |
| 72 | Pending | Required Linux↔Windows pair, Linux terminal after real reboot, and reverse Windows ConPTY workflow have not been physically performed. |
| 73 | Pending | No real Linux-to-Windows RDP forwarding/client acceptance evidence. |
| 74 | Partial | 2 GiB+17-byte transfer resumed at exactly 1 GiB after host process interruption with matching SHA-256 (`target/validation/large-transfer.log`). It does not meet the stated Internet interruption/recovery condition. |
| 75 | Implemented | Revocation prevents reauthentication and cancels streams; complete CLI E2E covers this flow (`crates/opengate-cli/tests/e2e.rs`; `target/validation/workspace-tests.log`). |
| 76 | Partial | Source, services, networking, CLI/TUI, tests, scripts, packages/workflows and documentation exist. Final current-tree gates, current Linux packages, Windows MSI construction/installation and platform acceptance are required before final delivery. |
| 77 | Partial | `BUILD_STATUS.md` contains Completed/Partial/Pending/Tests/Known limitations, and source favors working modules over pseudocode. Current official-API research and agent process cannot be proven from repository state. |
| 78 | Partial | The pair-once/trusted/reconnect/relay design is implemented and documented (`README.md`; `docs/ARCHITECTURE.md`). The promised cross-platform automatic availability experience awaits the acceptance evidence in §§72–74. |

## Evidence limits and release decision

The current local logs support Linux compilation/testing, local direct/relay
behaviour, Linux user-service crash restart, a Windows cross-build, and a large
file checkpoint recovery. They do **not** support a claim that Windows runtime,
MSI installation, real reboot, restrictive NAT/DCUtR, packet loss/interface
change, cross-platform terminal/RDP, or Internet-loss file resume has passed.
The optional integrated desktop GUI and signed auto-updater have a documented
future design and should not be substituted for required core acceptance.
