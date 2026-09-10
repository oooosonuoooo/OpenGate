# Troubleshooting

Start with `opengate status --network`, `opengate diagnose DEVICE` and `opengate logs`. Use the same `--data-dir` as the running daemon. `daemon.log` in that directory captures startup errors; security audit events are in SQLite.

| Symptom | Check and action |
|---|---|
| No daemon / startup timeout | Check listener port conflicts and the log. Separate test installations must use different ports/state directories. |
| Invalid invitation | Copy the complete OG1 token; check expiry and checksum. Generate a fresh token if used/cancelled. |
| Host visible but operation denied | Transport discovery does not grant access. Review that host's permission record for this device. |
| Full Admin denied | Both `allow_admin` and the peer's full-admin grant are required, and the daemon must already have OS privileges. |
| Direct connection fails | Check IPv6 and candidate addresses. Configure an authorized reachable relay on both peers and regenerate the invitation. |
| File path rejected | Use a relative path beneath the host's `file_root`; traversal and symlink escape are refused. |
| Destination exists | Verify the intended target, then explicitly pass `--overwrite`. |
| Transfer interrupted | Keep its checkpoint and retry with the same source/destination; do not rename or edit partial data. |
| Shell stopped during Internet loss | Reopen it after reconnection. Commands are not automatically replayed. |
| RDP/VNC does not connect | Enable the target desktop service through normal owner-approved OS settings and verify its loopback port. |
| Clipboard unavailable | Grant clipboard permission and run in an authorized interactive desktop session; install wl-clipboard/xclip as appropriate on Linux. |
| Revoked device still displayed | Its audit/history record remains; trusted=false means authentication is denied. |
| User daemon absent after reboot | Install the user service and arrange normal user-manager startup/linger, or install the explicitly chosen system service. |

Do not disable the firewall, Defender, UAC or Wayland security to work around a connection problem. Add only the required, deliberate inbound rules for your own relay or direct host listeners.

When reporting a problem, include version, OS, sanitized diagnostics, and whether the path is direct or relayed. Exclude pairing tokens, local API credentials, private keys and file/terminal content.
