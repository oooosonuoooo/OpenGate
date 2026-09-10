# Pairing and saved devices

`opengate allow` creates a 256-bit random enrollment secret with a 15-minute lifetime. `--ttl` accepts 60–900 seconds. A new token cancels the previous token; `opengate pairing cancel` invalidates the current invitation.

The printable base32 token contains the protocol version, host peer ID, expiry, secret, and candidate addresses. A SHA-256-derived checksum catches transcription errors. It is an invitation credential: anyone holding a live token can claim its grant. Share it privately and never put it in public tickets or logs.

The client pins the host's libp2p identity from the token before sending the secret inside the encrypted connection. The host verifies that the client's public key matches its authenticated transport identity. A SQLite transaction consumes the token and saves the trust record together. Concurrent claim attempts can succeed only once. The client then saves the host identity. Future authentication uses device keys, never the pairing token or a derived reusable shared password.

`opengate connect TOKEN --grant standard` grants the host reciprocal access to the client. Without `--grant`, the saved host receives view-only (diagnostic) access. Both endpoints store their own directional permission policy.

## Permissions

| Preset | Native terminal | Files | TCP forwarding | Desktop tunnel | Clipboard | Full Admin |
|---|---|---|---|---|---|---|
| view-only | No | No | No | No | No | No |
| standard | Yes | Yes | Yes | Yes | No | No |
| full-admin | Yes | Yes | Yes | Yes | No | Yes |

`view-only` currently permits device identification and diagnostics, not a restricted visual desktop session. RDP/VNC authentication and display/input permissions belong to the configured desktop server.

```console
opengate device permissions OFFICE-PC
opengate device permissions OFFICE-PC --preset standard
opengate device permissions OFFICE-PC --clipboard true
opengate device revoke OFFICE-PC
```

Full-admin grants require `--acknowledge-full-admin` and local `allow_admin = true`. A daemon running elevated rejects privileged remote operations unless both gates are enabled. A grant cannot elevate an unprivileged daemon.

Revocation marks the saved key untrusted, closes current OpenGate streams and disables its automatic reconnect tracking. The audit record is retained. Restoring access requires a newly authorized pairing. Permission changes cancel active streams so that the next operation is checked against the new policy.

A transport disconnect during the final pairing acknowledgment can leave a trust record on only one endpoint. Check both saved-device lists and generate a new invitation if necessary; do not weaken authentication to repair an incomplete enrollment.
