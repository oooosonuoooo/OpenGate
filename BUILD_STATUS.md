# OpenGate build status

Status: **implementation and release validation in progress**. The 78-section user specification is preserved in `docs/SPECIFICATION.md`. This project is not yet declared production-ready.

## Completed

- Rust Cargo workspace and lockfile; original Python prototype preserved under `legacy/python/`.
- Persistent Ed25519/libp2p identity, UUID, private Linux key storage, expiring checksummed 256-bit invitations, atomic single-use enrollment, saved directional trust and permissions, revocation and persistent replay IDs.
- Versioned bounded CBOR framing, separate remote service protocols, authenticated local daemon API and daemon state locking.
- CLI/TUI dispatch; native PTY/ConPTY service implementation; chunked SHA-256 file transfer, resumable checkpoints, capability-rooted file APIs; TCP, SSH, SOCKS and RDP/VNC forwarding implementations.
- Security, pairing, networking, relay, troubleshooting, development and installation documentation.

## Partially completed

- QUIC/TCP networking, Identify, Ping, mDNS, AutoNAT, relay v2 and DCUtR are implemented; direct/forced-relay/saved-restart tests passed. The large-file test exposed receive-buffer pressure and selection of a stale connection after restart; receive-window and transport-open retry fixes are under validation.
- Windows DPAPI/system-state DACL and Windows Service lifecycle are implemented. A real Windows x64 GNU release executable cross-build passed on 2026-09-10; PE imports contain only Windows system DLLs. Physical SCM, UAC, ConPTY and MSI installation remain unverified.
- Linux generated user unit startup, crash restart with stable identity, and clean shutdown passed under the real user service manager. DEB/RPM/portable archives were built; they will be rebuilt after the latest source fixes. WiX MSI construction was attempted and requires Windows; a directory component GUID error found during that check was fixed.
- File retry classification, progress/cancellation and safety tests passed in the current whole-workspace run. The release-mode 2 GiB + 17 byte transfer passed after a host process interruption at 1 GiB. The resumed offset and complete destination SHA-256 matched; this is process interruption evidence, not an Internet-outage test.
- Explicit clipboard get/send/sync exists with an independent permission. Actual desktop-provider integration is not yet verified.
- TUI pairing controls and device presentation exist. Long-token stdin acceptance, expired-invitation regeneration and sampled network throughput were corrected; final UI verification remains.

## Not yet implemented or verified

- Final production release artifacts and full final formatter/clippy/test/build/audit gates.
- Relay aggregate bandwidth control. Per-peer application-stream counters and optional per-stream, per-direction pacing are implemented and tested.
- Actual Linux↔Windows pairing, reverse ConPTY shell, Windows RDP connection, real reboot, real restrictive-NAT/hole-punch, packet-loss and interface-change validation.
- Signed release/update trust distribution. Unsigned automatic download/execution is disabled. The signed-manifest, key-rotation, rollback and migration contract is documented in `docs/UPDATE-DESIGN.md`; automatic signed delivery is a future release stage.
- Optional integrated screen-capture/input desktop engine and GUI are deferred stages; desktop service tunneling is the initial module.

## Tests passed

Linux validation on 2026-09-10, before the latest receive-window/retry and CLI input changes (a final rerun is required):

- `cargo check --workspace`: passed with Hickory 0.26.2 and Ratatui 0.30.2.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: passed.
- `cargo test --locked --workspace`: 39 passed, no failures, one separately invoked large test ignored in the normal suite. Covers real daemon pairing/PTY/file/TCP/restart/revocation, forced relay, saved-peer reconnect, database concurrency, malformed frames, path confinement, durable transfer resume, permission and cancellation behavior.
- `cargo audit`: exit 0; no known vulnerabilities, one documented unmaintained `paste` transitive macro warning. See `vendor/README.md` for the upstream DNS compatibility patches and warning assessment.
- Windows x64 GNU release build: passed. Output: `target/windows-validation/x86_64-pc-windows-gnu/release/opengate.exe`. Static PE inspection confirms Windows system DLL imports; runtime and MSI installation remain untested.
- Release-mode large transfer: 2,147,483,665 bytes verified, resumed from 1,073,741,824 bytes after host process interruption; test completed in 92.30 seconds. Evidence: `target/validation/large-transfer.log`.
- Generated Linux user unit: startup, forced-crash restart with unchanged identity, and clean stop passed. Evidence: `target/validation/linux-service.log`.
- Linux bootstrap dry run and shell syntax checks: passed without installing packages or changing services.

Evidence is saved as matching `.log` and `.exit` files under `target/validation/`.

## Known limitations

- Loopback tests do not prove Internet/CGNAT traversal or operating-system reboot behavior. A process restart is explicitly distinct from a machine reboot.
- Existing TCP byte streams and shell commands are never replayed automatically. File transfers resume from durable checkpoints.
- `libp2p-stream` is the upstream 0.4.0-alpha API, pinned in Cargo.lock; its prerelease status must be considered before release.
- Standard shell permission grants the daemon account's OS capabilities. File-only access is separately constrained to the configured file root.
- Full Admin requires deliberate privileged service configuration plus explicit per-device permission; it does not bypass UAC/sudo.
- This machine currently supplies Linux verification. Windows cross-build results will not be represented as physical Windows runtime testing.

Saved validation logs under `target/validation/` contain check output, not private identity or pairing state. No production site/service was changed by these implementation checks.
