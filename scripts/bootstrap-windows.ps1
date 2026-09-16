[CmdletBinding()]
param([switch]$Apply, [switch]$InstallOpenSshServer)

$ErrorActionPreference = 'Stop'
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($arch -ne 'X64') {
  throw "This release bootstrap currently supports Windows x64; detected $arch."
}

function Find-MsvcBuildTools {
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { return $null }
  $installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
  if ([string]::IsNullOrWhiteSpace($installation)) { return $null }
  $devCmd = Join-Path $installation.Trim() 'Common7\Tools\VsDevCmd.bat'
  if (-not (Test-Path -LiteralPath $devCmd -PathType Leaf)) { return $null }
  return $devCmd
}

function Invoke-MsvcCommand([string]$DevCmd, [string]$Command) {
  # VsDevCmd is a batch file, so import its environment in a child cmd.exe that
  # runs cargo and WiX with the supported x64 MSVC toolchain available.
  & cmd.exe /d /s /c "call `"$DevCmd`" -arch=x64 -host_arch=x64 >nul && $Command"
  if ($LASTEXITCODE -ne 0) { throw "Command failed ($LASTEXITCODE): $Command" }
}

Write-Host 'OpenGate Windows x64 bootstrap'
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
$devCmd = Find-MsvcBuildTools
if ($cargo) { Write-Host "Rust: $($cargo.Source)" } else { Write-Host 'Rust: not found' }
if (Get-Service sshd -ErrorAction SilentlyContinue) { Write-Host 'OpenSSH Server: installed.' } else { Write-Host 'OpenSSH Server: not installed. Select -InstallOpenSshServer to install and enable it.' }
if ($devCmd) { Write-Host "MSVC Build Tools: $devCmd" } else { Write-Host 'MSVC Build Tools: not found' }
Write-Host 'The installer contains compiled binaries; end users do not need Rust or Visual Studio.'
if (-not $Apply) {
  Write-Host 'Dry run only. -Apply installs missing developer prerequisites, then builds, tests, and creates target\OpenGate.msi.'
  if (-not $cargo) { Write-Host 'Rust will be installed using the official rustup-init.exe.' }
  if (-not $devCmd) { Write-Host 'Visual Studio Build Tools with the C++ workload will be installed through winget when available.' }
  if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { Write-Host 'Microsoft .NET 8 SDK will be installed through winget to build the MSI.' }
  if ($InstallOpenSshServer) { Write-Host 'OpenSSH.Server will be installed only because -InstallOpenSshServer was selected.' }
  exit 0
}

if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
  $rustup = Join-Path $env:TEMP 'rustup-init.exe'
  Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile $rustup
  & $rustup -y --profile minimal --default-toolchain 1.98.1
  if ($LASTEXITCODE -ne 0) { throw "rustup installation failed ($LASTEXITCODE)" }
  $env:PATH = (Join-Path $env:USERPROFILE '.cargo\bin') + ';' + $env:PATH
}
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
  throw 'Rust installed, but cargo is not available in this session. Open a new PowerShell window and rerun the bootstrap.'
}

if (-not $devCmd) {
  $winget = Get-Command winget -ErrorAction SilentlyContinue
  if (-not $winget) {
    throw 'Microsoft C++ Build Tools are required. Install them from Visual Studio Installer with the Desktop development with C++ workload, then rerun this script.'
  }
  & $winget.Source install --id Microsoft.VisualStudio.2022.BuildTools --exact --accept-package-agreements --accept-source-agreements --override '--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'
  if ($LASTEXITCODE -ne 0) { throw "Visual Studio Build Tools installation failed ($LASTEXITCODE)" }
  $devCmd = Find-MsvcBuildTools
  if (-not $devCmd) { throw 'Visual Studio Build Tools finished but the MSVC x64 toolchain was not found. Rerun after installation completes.' }
}

if ($InstallOpenSshServer) {
  Write-Host 'Requested system changes: install OpenSSH Server and set/start the sshd service. Windows may add its standard SSH firewall rule.'
  $capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
  if ($capability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
  }
  Set-Service -Name sshd -StartupType Automatic
  Start-Service -Name sshd
}

if (Get-Command rustup -ErrorAction SilentlyContinue) {
  & rustup toolchain install 1.98.1 --profile minimal --component rustfmt --component clippy
  if ($LASTEXITCODE -ne 0) { throw 'Rust 1.98.1 toolchain setup failed.' }
}
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
  $winget = Get-Command winget -ErrorAction SilentlyContinue
  if (-not $winget) { throw 'Install the .NET 8 SDK using Microsoft tooling, then rerun to build the WiX installer.' }
  Write-Host 'Installing Microsoft .NET 8 SDK through winget to build the MSI.'
  & $winget.Source install --id Microsoft.DotNet.SDK.8 --exact --accept-package-agreements --accept-source-agreements
  if ($LASTEXITCODE -ne 0) { throw '.NET SDK installation failed.' }
  $env:PATH = (Join-Path $env:ProgramFiles 'dotnet') + ';' + $env:PATH
  if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw 'Reopen PowerShell after .NET installation, then rerun this bootstrap.' }
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Push-Location $repo
try {
  if (Get-Command rustup -ErrorAction SilentlyContinue) {
    Invoke-MsvcCommand $devCmd 'cargo +1.98.1 build --locked --release && cargo +1.98.1 test --locked --workspace'
  } else {
    Invoke-MsvcCommand $devCmd 'cargo build --locked --release && cargo test --locked --workspace'
  }
  & dotnet tool update --global wix --version '4.0.6'
  if ($LASTEXITCODE -ne 0) { throw "WiX installation failed ($LASTEXITCODE)" }
  $wix = Join-Path $env:USERPROFILE '.dotnet\tools\wix.exe'
  if (-not (Test-Path -LiteralPath $wix -PathType Leaf)) { throw "WiX executable not found: $wix" }
  & $wix extension add WixToolset.Util.wixext
  if ($LASTEXITCODE -ne 0) { throw "WiX extension installation failed ($LASTEXITCODE)" }
  $version = ([regex]::Match((Get-Content -Raw 'Cargo.toml'), '(?m)^version\s*=\s*"([^"]+)"')).Groups[1].Value
  if ([string]::IsNullOrWhiteSpace($version)) { throw 'Could not determine the OpenGate package version from Cargo.toml.' }
  & $wix build -arch x64 'packaging\windows\OpenGate.wxs' -ext WixToolset.Util.wixext -d "OpenGateBinary=$repo\target\release\opengate.exe" -d "ProductVersion=$version" -o 'target\OpenGate.msi'
  if ($LASTEXITCODE -ne 0) { throw "WiX MSI build failed ($LASTEXITCODE)" }
} finally {
  Pop-Location
}
