[CmdletBinding()]
param([switch]$Apply, [switch]$InstallOpenSsh)
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($arch -notin @('X64','Arm64')) { throw "Unsupported architecture: $arch" }
Write-Host "OpenGate Windows bootstrap: $arch"
Write-Host "Changes on -Apply: download the official rustup-init.exe and install Rust for this user."
if ($InstallOpenSsh) { Write-Host "Also requested: install OpenSSH.Client capability." } else { Write-Host "OpenSSH will not be installed." }
if (-not $Apply) { Write-Host "Dry run only. Re-run with -Apply to make changes."; exit 0 }
if ($InstallOpenSsh) { Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 }
$tmp = Join-Path $env:TEMP 'rustup-init.exe'
Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile $tmp
& $tmp -y --profile minimal
if ($LASTEXITCODE -ne 0) { throw "rustup installation failed ($LASTEXITCODE)" }
Write-Host "Rust installed. Open a new PowerShell window, then run: cargo build --release"
