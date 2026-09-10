# OpenGate security

OpenGate provides visible, owner-authorized remote access. It does not implement stealth persistence, credential collection, keylogging, security-control bypass, or unauthorized privilege escalation.

## Trust and encryption

Each installation generates an independent Ed25519/libp2p identity and random device UUID. QUIC uses authenticated TLS; TCP and relay streams use libp2p's authenticated encryption. A network connection alone grants no application permission. Every service stream is checked against persistent local trust and the requested operation's permission.

Pairing uses a random 256-bit, expiring, single-use secret inside an encrypted connection pinned to the token's host identity. Private device keys are never included in invitation tokens or the application protocol. Only token hashes are stored by the host. A transaction consumes the invitation and records the authorized peer.

Linux key files are owner-only with mode 0600 inside a 0700 state directory. Protected files reject symlinks, unexpected ownership, unsafe permissions and hard links. Windows uses DPAPI; system-service account and management access must use an explicit ACL-protected arrangement. Consult BUILD_STATUS for the current Windows validation boundary.

The SQLite trust database records public identities, permissions, nickname, address hints and timestamps. Unknown/revoked peers are rejected. Revocation and permission changes cancel active OpenGate streams. Terminal launch requests carry persistent replay IDs; reconnect never blindly resends commands.

## Privilege boundaries

Standard terminal access permits the privileges of the daemon's operating-system account. It is powerful: a shell can access that account's files and application state. Restrict terminal grants to administrators you trust with that account. File-only access is restricted to the configured capability root; OS permissions still apply.

Full Admin Access means the owner deliberately configured an administrator/root-capable service and explicitly granted a peer permission to use that capability. It does not mean bypassing UAC, sudo, operating-system access controls or exploiting vulnerabilities. Both `allow_admin` and the peer's `full_admin` permission are required for elevated remote operations.

The local management API binds loopback and requires a protected random credential. Any process acting as the same local OS identity already shares that identity's privileges; OpenGate does not isolate malicious code running as its owner. System service management must additionally respect the service account's state protection.

Clipboard permissions are independent, disabled by default and use the owner's official desktop facilities. A headless service cannot bypass Wayland or access another desktop session. RDP/VNC tunnel contents remain controlled by that server/client; OpenGate cannot inspect or selectively revoke RDP's internal clipboard channels.

## Input and resource controls

Frames contain magic, version, request ID, message type and payload length; malformed/oversized frames are rejected. File transfers use bounded chunks and verify SHA-256 before publication. Capability-relative file paths reject traversal and symlink escape. TCP listeners default to loopback. Connection/stream limits, deadlines and pairing rate controls constrain untrusted clients; relay resource limits constrain infrastructure use.

Logs record security events, not pairing secrets, private keys, clipboard contents or terminal output. Do not enable arbitrary third-party trace logging in production without assessing what that dependency records. Never paste live tokens or state files into public issue reports.

## Threat model and limitations

In scope: unauthorized remote peers, invitation replay, malformed messages, file-root escape, revoked access, abusive connection attempts, and an untrusted relay. A stolen live invitation can be used until it expires or is consumed. A stolen private device key requires revocation on every trusting device. Endpoint compromise, malicious local administrators, denial of Internet service and an untrusted remote OS remain outside the cryptographic transport's protection.

This is not a claim of independent security certification. Unverified operating-system paths, external NAT tests and remaining hardening are recorded in BUILD_STATUS. Automatic unsigned updates are disabled. Release signing keys and signing credentials are not embedded in this repository.

## Reporting a vulnerability

A security contact has not yet been configured for this unpublished project. Contact the repository owner privately and agree on an encrypted reporting channel before sending exploit details. Include affected version, platform, impact, a minimal reproduction and any mitigations. Do not include keys, tokens or personal files. The repository must configure a private reporting contact before public release.
