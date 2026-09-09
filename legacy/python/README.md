# OpenGate

OpenGate is a small cross-platform remote-access transport for **your own Windows and Linux machines**. It gives the user the two workflows requested:

1. **Connect** — pair a new host with a token or choose a previously saved device.
2. **Get connected** — run the host service and generate a pairing token.

OpenGate does **not** implement a hidden remote-command engine. It transports the target machine's normal **OpenSSH** connection. That gives you the same capabilities and security model as normal SSH while keeping the OpenGate layer small.

## What this build already does

- Windows ↔ Linux, Linux ↔ Windows, Windows ↔ Windows, Linux ↔ Linux.
- Single-use pairing token, valid for 15 minutes by default.
- Pair once, then the controller is saved on both sides.
- Later connections use a saved device secret; no pairing token is required again.
- Host automatically starts again after reboot when installed with the supplied scripts.
- Optional controller auto-start scripts keep the local proxy available after reboot/login.
- New SSH connections retry while the host or Internet connection is temporarily unavailable.
- The host only forwards to a **loopback** service (`127.0.0.1:22` by default).
- Challenge-response HMAC authentication; the reusable secret is never transmitted during normal authentication.
- SSH itself provides end-to-end encryption and SSH host-key verification for the actual remote shell traffic.
- Standard-library-only Python source; no third-party Python package is required to run it.

## Important Internet/NAT limitation

A machine behind ordinary NAT/CGNAT usually cannot accept an unsolicited Internet connection. If **both** peers are private, no program can guarantee universal serverless connectivity with all of these constraints simultaneously:

- no router port mapping,
- no public IPv6/reachable address,
- no rendezvous/coordination service,
- no relay service.

This build therefore implements the complete **direct-connect core**. It works when the host address in the token is reachable (LAN, public IPv4 with routing, public IPv6, VPN, or an existing reachable endpoint).

For a Tailscale-like "works behind almost every NAT" product, OpenGate needs a small **coordination/rendezvous component** for NAT discovery/hole-punching and, on restrictive/symmetric NATs, an optional relay fallback. The SSH data can remain direct whenever hole punching succeeds. A signaling-only server cannot guarantee success on every NAT.

## Administrator/root access

OpenGate does not bypass the operating system's security controls.

- **Linux:** SSH into a normal administrative account and use `sudo`; root SSH remains controlled by your existing `sshd_config`.
- **Windows:** SSH into an account that already belongs to Administrators (for example, an enabled Administrator account) using Windows OpenSSH.

The installer does not disable UAC, weaken SSH authentication, enable blank passwords, or silently enable root login.

---

# Linux

## Host / "Get connected"

From the extracted OpenGate folder:

```bash
sudo ./scripts/install-linux.sh --mode host
```

The installer:

- installs Python 3 if needed,
- installs OpenSSH Server if needed,
- installs OpenGate under `/opt/opengate`,
- creates `/usr/local/bin/opengate`,
- creates and enables `opengate-host.service`,
- enables SSH,
- opens the local firewall port when UFW/firewalld is active.

Generate a token:

```bash
sudo opengate token --system --advertise 192.168.1.50:44344
```

For Internet use, replace the address with a **reachable** public address or DNS name:

```bash
sudo opengate token --system --advertise my-pc.example.net:44344
```

The token is single-use and expires after 15 minutes.

Check the host:

```bash
systemctl status opengate-host
systemctl status ssh || systemctl status sshd
```

## Controller / "Connect"

```bash
./scripts/install-linux.sh --mode controller
```

Pair once:

```bash
opengate connect --token 'OG1.YOUR_TOKEN_HERE'
```

OpenGate stores the device and exposes a local SSH endpoint at `127.0.0.1:2222`.

Then use normal SSH:

```bash
ssh -p 2222 your-linux-user@127.0.0.1
```

For a Windows target:

```bash
ssh -p 2222 Administrator@127.0.0.1
```

Later you do not need the token:

```bash
opengate devices
opengate connect --device HOSTNAME
```

Enable controller auto-start for one saved device:

```bash
./scripts/enable-controller-linux.sh HOSTNAME 2222
```

The script creates a user systemd service and attempts to enable `loginctl` linger so the proxy can start at boot without an interactive login.

---

# Windows

Open PowerShell in the extracted folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

## Host / "Get connected"

```powershell
.\scripts\install-windows.ps1 -Mode Host
```

The installer requests Administrator elevation and then:

- installs Python 3 system-wide if needed (using `winget`),
- installs Windows OpenSSH Server,
- sets `sshd` to Automatic and starts it,
- installs OpenGate under `C:\Program Files\OpenGate`,
- creates an inbound Windows Firewall rule for TCP 44344,
- creates an `OpenGate Host` scheduled task running as SYSTEM at startup.

Open a **new Administrator terminal** and create a token:

```powershell
opengate token --system --advertise 192.168.1.50:44344
```

## Controller / "Connect"

```powershell
.\scripts\install-windows.ps1 -Mode Controller
```

Open a new terminal, pair once, and then SSH:

```powershell
opengate connect --token 'OG1.YOUR_TOKEN_HERE'
ssh -p 2222 Administrator@127.0.0.1
```

Later:

```powershell
opengate devices
opengate connect --device HOSTNAME
```

Enable controller auto-start at Windows logon:

```powershell
.\scripts\enable-controller-windows.ps1 -Device HOSTNAME -LocalPort 2222
```

---

# Interactive mode

Running OpenGate without arguments shows the requested two main choices:

```text
OpenGate
1) Connect
2) Get connected
3) Saved devices
```

Run:

```bash
opengate
```

or, before installation:

```bash
python3 opengate.py
```

---

# Useful commands

```text
opengate host [--system]
opengate token [--system] [--advertise HOST:PORT]
opengate connect --token TOKEN
opengate connect --device NAME
opengate devices
opengate remove NAME
opengate authorized [--system]
opengate revoke CONTROLLER_ID [--system]
```

`authorized` and `revoke` let the host owner see and revoke controllers.

# Reconnection behavior

The host installer configures automatic restart after OS reboot. The controller proxy can also be configured for auto-start.

When the host/network is temporarily unavailable, a **new local SSH connection** waits and retries for up to 120 seconds by default:

```bash
opengate connect --device HOSTNAME --retry-seconds 300
```

An SSH TCP session that has already been destroyed by a long Internet outage or a reboot cannot be transparently resumed as the same TCP/SSH session. On Linux, use `tmux` or `screen` on the remote host if you want your shell processes to survive a disconnect.

# Build a standalone executable (optional)

The runtime itself needs only Python. If you prefer a single executable, the supplied scripts use PyInstaller.

Linux:

```bash
./scripts/build-standalone.sh
```

Windows:

```powershell
.\scripts\build-standalone-windows.ps1
```

# Current security notes

This is a working MVP, not yet a security-audited production remote-access product. Before commercial deployment, recommended hardening includes:

- store controller secrets in Windows DPAPI / Linux Secret Service or another OS-backed key store,
- signed application updates,
- structured audit logging and log rotation,
- brute-force/rate-limit controls,
- NAT discovery/rendezvous with authenticated metadata,
- direct-path verification when adding hole punching,
- installer signing on Windows and signed packages/repositories on Linux,
- independent security review and penetration testing.

See `SECURITY.md` and `ARCHITECTURE.md`.
