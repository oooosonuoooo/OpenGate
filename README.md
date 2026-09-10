# OpenGate

Pair once, then securely access your authorized Windows and Linux computers whenever a viable network path is available.

OpenGate is a Rust application with a reusable networking engine, native PTY/ConPTY terminal, file transfer, TCP forwarding, a local daemon, and self-hosted relay support. Each installation can host and connect. It has no cloud-account requirement.

**Release status:** active implementation and acceptance testing. Read [BUILD_STATUS.md](BUILD_STATUS.md) before deploying it. The preserved Python prototype in `legacy/python/` uses a different protocol and is not the Rust application's runtime.

## Start on two computers

Install a compiled package using [Linux installation](INSTALL-LINUX.md) or [Windows installation](INSTALL-WINDOWS.md). Developers can build with `cargo build --release --locked`; the executable is `target/release/opengate` (`.exe` on Windows).

On computer A:

```console
opengate allow
```

This starts the user daemon if needed, displays the device identity and creates a 15-minute, single-use token. Copy the entire token privately to computer B:

```console
opengate connect OG1-...
opengate devices
opengate shell COMPUTER-A
```

Use the hostname or peer ID shown by `devices`. An optional nickname is set with `opengate device rename 1 OFFICE-PC`. Future connections use persistent Ed25519 identities; a used pairing token is not retained as the authentication credential.

A pairing grant is directional. `allow` grants standard access to the connecting device. Computer B saves computer A with diagnostic-only access by default. For reciprocal terminal/file/tunnel access use `opengate connect TOKEN --grant standard`, or change permissions explicitly on the computer receiving access.

The pairing code includes the pinned peer ID and address hints, so it is longer than a short numeric invitation. It contains no private device key. Passing tokens as command arguments can expose them to local process inspection and shell history; the interactive `opengate` menu accepts a token without putting it in a command argument.

## Everyday commands

```console
opengate
opengate status --network
opengate devices
opengate diagnose OFFICE-PC
opengate shell OFFICE-PC
opengate forward OFFICE-PC --local 2222 --remote 127.0.0.1:22
opengate push OFFICE-PC ./backup.zip backup.zip
opengate pull OFFICE-PC backup.zip ./downloaded-backup.zip
opengate files OFFICE-PC list .
opengate desktop OFFICE-PC --local 13389
opengate device revoke OFFICE-PC
opengate pairing cancel
```

Forwarding carries conventional SSH, HTTP, databases, RDP or VNC through the encrypted peer connection. Those services retain their own login and operating-system policies. The native OpenGate terminal does not require OpenSSH.

File paths are relative to the host's configured `file_root`, initially its private `shared` directory. Directory uploads/downloads recurse with separate file streams. Existing files require `--overwrite`. Interrupted file transfers retain checkpoints; interactive shell commands and existing TCP byte streams are never replayed automatically.

## Connectivity and privileges

LAN discovery does not grant trust. QUIC is preferred, TCP provides a fallback, and configured relay nodes support restrictive networks. Some NAT/CGNAT combinations require a publicly reachable relay. Run your own with `opengate relay`; see [NETWORKING.md](NETWORKING.md) and [RELAY.md](RELAY.md).

OpenGate automatically reconnects whenever a viable network path becomes available. Physical network failure can interrupt connectivity. A direct path or hole punch is never guaranteed for arbitrary networks.

Full Admin Access requires both an explicitly privileged service configuration and an explicit per-device grant. It does not bypass UAC, sudo or OS access controls. See [SECURITY.md](SECURITY.md).

## Project documentation

- [Pairing and permissions](PAIRING.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Development and verification](DEVELOPMENT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Original requirements](docs/SPECIFICATION.md)
- [Current build evidence and remaining work](BUILD_STATUS.md)
