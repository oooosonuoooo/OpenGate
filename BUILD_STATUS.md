# OpenGate build status

Status: **source implementation and local release validation complete; native
Windows and physical cross-platform acceptance remain pending**. The 78-section
specification is preserved in [docs/SPECIFICATION.md](docs/SPECIFICATION.md),
and the requirement-by-requirement audit is in
[docs/REQUIREMENTS-AUDIT.md](docs/REQUIREMENTS-AUDIT.md). No production host,
service, database, or external release channel was changed.

## Completed

- Rust workspace and nine crate boundaries, persistent Ed25519/libp2p identity,
  UUID and protected key storage, one-use checksummed pairing tokens, SQLite
  trust/replay/audit records, directional permissions, revocation, and explicit
  full-admin acknowledgement.
- Bounded versioned CBOR framing with stable typed error codes, request IDs,
  domain error preservation and retryability; authenticated local daemon API,
  state locking, and protected loopback credentials.
- QUIC-preferred TCP/Noise/Yamux networking with Identify, Ping, mDNS, AutoNAT,
  Circuit Relay v2, DCUtR, saved-peer reconnect, route/transport/latency/loss
  selection, and relay pacing/quotas. New streams prefer the best current path;
  existing streams are not replayed or silently migrated.
- Native Linux PTY and Windows ConPTY source, cancellation-safe terminal
  streams, capability-rooted file operations, directory transfers, SHA-256
  checkpoints/resume, TCP/SOCKS/RDP/VNC forwarding, and opt-in clipboard APIs.
- CLI/TUI workflows, diagnostics and connection display, per-device reconnect
  preferences with schema migration, configuration validation, service helpers,
  Linux user-service support, Windows service source, WiX MSI source, and
  Linux/Windows bootstrap scripts.
- CI and release workflows, dependency audit wiring, update-signing design,
  security/architecture/networking/relay/install/troubleshooting documentation,
  and an isolated Linux network namespace harness that applies real delay,
  packet loss, outage, restore and automatic resume.

## Validation completed

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: passed.
- `cargo test --locked --workspace`: 43 passed, no failures; one separately
  invoked large transfer test remains ignored in the normal suite.
- `cargo audit`: exit 0; no known vulnerabilities. The only report is the
  documented unmaintained transitive `paste` macro warning; see
  [vendor/README.md](vendor/README.md).
- Linux release build and Windows x86_64 GNU release cross-build: passed.
  The Windows PE imports contain only Windows system DLLs.
- Final release-mode 2 GiB + 17 byte transfer: passed after host-process
  interruption, with durable checkpoint and matching SHA-256.
- Current-binary isolated network acceptance: two user/net namespaces,
  two routed subnets, 15 ms delay and 0.2% loss per direction, a 100% loss
  outage after halfway, automatic saved-trust reconnect, checkpoint-preserving
  CLI resume, and matching SHA-256. The generated local output is intentionally
  ignored by Git; rerun the command in [DEVELOPMENT.md](DEVELOPMENT.md) to
  reproduce it.
- Current-binary TUI smoke and generated Linux user-service test passed;
  the latter started, restarted after SIGKILL with an unchanged identity, and
  stopped cleanly.
- Final DEB, RPM, portable Linux archive, Windows ZIP and Windows MSI artifacts
  were rebuilt. `target/packages/SHA256SUMS` verifies all five. MSI extraction
  confirms the embedded executable hash matches the final Windows executable;
  service install, recovery, LocalService identity and protected data-directory
  ACL rows are present in the MSI tables.

Validation output, exit codes, and release packages are generated under the
ignored `target/` directory. They are intentionally not part of a GitHub
checkout; the commands in [DEVELOPMENT.md](DEVELOPMENT.md) reproduce the
checks and package artifacts.

## Pending physical acceptance

- A native Windows run is still required for SCM start/stop/recovery, UAC and
  privilege boundaries, DPAPI/DACL behavior, ConPTY, MSI install/upgrade/
  uninstall, and Windows bootstrap execution.
- A real Linux-to-Windows pair is still required for cross-platform PTY,
  RDP/VNC forwarding, file resume on the Windows filesystem, and the complete
  desktop-provider clipboard path.
- Physical reboot, sleep/wake, interface-change, restrictive NAT/CGNAT and
  Internet DCUtR behavior are not reproducible in this Linux workspace. The
  source, controlled namespace harness, and diagnostics are implemented, but
  these claims require the stated hardware/network test matrix.

## Deliberate future scope

- The optional integrated screen-capture/input desktop engine and GUI remain
  future stages; the current desktop capability is the documented tunnel
  module.
- Signed update manifests, key rotation, rollback and migration are documented
  in [docs/UPDATE-DESIGN.md](docs/UPDATE-DESIGN.md). Automatic download and
  execution stays disabled until a signing and release service is supplied.
- ARM artifacts and a hosted GitHub Actions run are not represented by this
  local x86_64 validation; the workflows are present for the release
  environment.

The current evidence supports the implemented Linux behavior, cross-built
Windows artifacts, local direct/relay behavior, durable transfer recovery,
typed errors, and package structure. It does not claim native Windows runtime
or physical Internet/NAT/reboot acceptance until those tests are performed.
