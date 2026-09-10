# Development

The workspace uses Rust stable, edition 2024, and Cargo.lock. Install the stable toolchain and rustfmt/clippy through rustup; use the bootstrap scripts for OS-specific development prerequisites. Runtime users install compiled packages and do not need Cargo, Python, Node or Visual Studio.

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo build --workspace --release --locked
cargo audit
```

`.cargo/config.toml` limits build concurrency to two jobs for this development machine. Increase it explicitly if your machine has sufficient memory.

The CLI integration test launches separate daemon processes in temporary state directories on random loopback ports. It covers pairing, token reuse rejection, native PTY, file integrity, TCP forwarding, permission downgrade, daemon restart and revocation. It never interrupts the host's real network or changes its services.

Network crate tests must distinguish direct QUIC, forced relay and automatic reconnect. A three-node loopback relay test proves relay protocol interoperability, not real NAT traversal. External Windows/Linux machines remain necessary for the cross-OS acceptance matrix, actual reboot, ConPTY/UAC/SCM validation and restrictive-NAT behavior.

Protocol services live in reusable crates. The daemon owns trust, authorization, cancellation and the local management API. A future GUI should use the local API rather than opening a second swarm with the same identity. One installation/state directory is one daemon identity.

See [the original requirements](docs/SPECIFICATION.md) and [BUILD_STATUS](BUILD_STATUS.md) for implementation and evidence gaps. Preserve user trust/config data through upgrades and uninstall. Never put test secrets, production state or signing keys in Git.

## Extended acceptance checks

The opt-in large-file test writes over 2 GiB, interrupts the host process after
1 GiB, and verifies the resumed destination checksum. Run it in release mode to
avoid slow debug hashing:

```console
cargo test --locked -p opengate-cli --release --test e2e multi_gigabyte_transfer_resumes_after_peer_interruption -- --ignored --nocapture
```

A Linux machine with a running systemd user manager can exercise the generated
unit, crash recovery and clean stop with:

```console
python3 scripts/test-linux-service.py
```

This creates a uniquely named runtime unit and temporary state, then removes
both. It does not enable a persistent service, reboot the machine or stop an
existing installation. Python is only a developer test dependency.

Dependency compatibility patches and upstream provenance are recorded in
`vendor/README.md`. This build requires Rust 1.98 or later; Cargo.lock pins the
validated dependency graph. Windows x64 builds can be cross-compiled with the
Rust GNU target and a matching MinGW GNU toolchain. WiX MSI construction and
installation must run on Windows; Linux PE linking does not validate SCM,
DPAPI, ConPTY, UAC or RDP.
