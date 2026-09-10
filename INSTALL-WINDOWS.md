# Install OpenGate on Windows

The MSI is a per-machine installer. Run it from Explorer or an elevated command
prompt and accept the normal Windows UAC prompt. It installs the executable in
`Program Files\OpenGate` and creates the automatic `OpenGate` Windows service
under `NT AUTHORITY\LocalService`. The service starts on installation and is
configured to restart after failures.

The default service state is under:

```text
C:\ProgramData\OpenGate
```

The installer creates this directory with a protected ACL before the service is
started. On first start, OpenGate creates its machine-DPAPI-protected device
identity there and replaces the temporary LocalService ACL entry with the
OpenGate service identity. SYSTEM and local Administrators retain access for
recovery. Use an elevated Administrator terminal for system-service management:

```powershell
& 'C:\Program Files\OpenGate\opengate.exe' --data-dir "$env:ProgramData\OpenGate" service status
```

Normal users can run OpenGate in their own user mode, which uses separate
per-user state. Do not copy, loosen ACLs on, or try to decrypt the system
service state from a normal-user session.

## Script installation

From an elevated PowerShell prompt:

```powershell
.\scripts\install-windows.ps1 -Binary .\target\release\opengate.exe
```

The script asks for UAC elevation itself if necessary. It does not disable UAC,
Defender, or add antivirus exclusions.

## Full Admin Access

Full Admin Access requires both owner configuration and an explicit installer
choice. In an elevated Administrator terminal, enable `allow_admin` for the
existing system-service state only after reviewing the trusted peer:

```powershell
& 'C:\Program Files\OpenGate\opengate.exe' --data-dir "$env:ProgramData\OpenGate" config set allow_admin true
```

Then reinstall the service with the explicit flag:

```powershell
.\scripts\install-windows.ps1 -Binary .\target\release\opengate.exe -FullAdmin
```

This changes the service account to LocalSystem. The service identity and state
remain protected; the installer never grants ordinary Users access. Remove the
owner setting and rerun the script without `-FullAdmin` to return to the
least-privileged LocalService account.

An MSI upgrade preserves the state directory, device identity, and saved
devices. It deliberately reinstalls the default least-privileged LocalService
account; if Full Admin Access is still wanted after an upgrade, review the
trusted peer again and rerun the script with `-FullAdmin`.

Do not grant a peer Full Admin Access unless the owner has explicitly approved
that peer's saved-device permission as well.
