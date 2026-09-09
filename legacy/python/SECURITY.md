# Security notes

OpenGate is intended for systems you own or are explicitly authorized to administer.

## Security properties in this MVP

- Pairing tokens expire and are single-use.
- Normal authentication uses a fresh random challenge and HMAC-SHA-256.
- The reusable controller secret is not transmitted during normal authentication.
- The host forwards only to a loopback address.
- The default target is the local OpenSSH server on port 22.
- OpenGate itself does not accept arbitrary OS commands.
- Remote user authentication and privilege remain under OpenSSH/Windows/Linux policy.
- Linux configuration files are created with restrictive permissions where possible.

## Important limitations

- Saved secrets are protected primarily by filesystem/account permissions, not yet by an OS hardware/keychain-backed secure store.
- The direct transport metadata itself is not a replacement for SSH encryption. The actual remote administration traffic is expected to be SSH, which is encrypted and authenticated by SSH host keys.
- The project has not received an independent security audit.
- Direct TCP connectivity does not solve NAT/CGNAT universally.

## Production recommendations

Before exposing a production build broadly to the Internet:

1. Move device secrets to DPAPI on Windows and a suitable OS secret store on Linux.
2. Add connection rate limits, temporary bans, and audit events.
3. Sign Windows executables/installers and Linux packages.
4. Add signed automatic updates with rollback protection.
5. Add authenticated NAT rendezvous and direct-path verification.
6. Add unit, integration, fuzz, and protocol-compatibility tests.
7. Commission an independent security assessment.
