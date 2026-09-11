[CmdletBinding()]
param([string]$Binary = '.\target\release\opengate.exe', [switch]$FullAdmin)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { throw "Binary not found: $Binary" }
$Binary = (Resolve-Path -LiteralPath $Binary -ErrorAction Stop).Path
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'Requesting administrator approval to install the OpenGate service...'
  $arguments = "-NoProfile -File `"$PSCommandPath`" -Binary `"$Binary`""
  if ($FullAdmin) { $arguments += ' -FullAdmin' }
  $elevated = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList $arguments
  exit $elevated.ExitCode
}
$destination = Join-Path $env:ProgramFiles 'OpenGate'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$data = Join-Path $env:ProgramData 'OpenGate'
if ($FullAdmin) {
  $config = Join-Path $data 'config.toml'
  if (-not (Test-Path $config -PathType Leaf) -or -not (Select-String -Path $config -Pattern '^\s*allow_admin\s*=\s*true\s*(?:#.*)?$' -Quiet)) {
    throw "Full Admin requires the existing owner configuration $config to contain allow_admin = true. It is never enabled automatically."
  }
}
$existing = Get-Service OpenGate -ErrorAction SilentlyContinue
$wasRunning = $existing -and $existing.Status -eq 'Running'
$installedBinary = Join-Path $destination 'opengate.exe'
$backup = Join-Path $destination 'opengate.previous.exe'
if ($existing) {
  Stop-Service OpenGate
  (Get-Service OpenGate).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
try {
  if ((Test-Path -LiteralPath $installedBinary) -and $Binary -ne $installedBinary) {
    Copy-Item -LiteralPath $installedBinary -Destination $backup -Force
  }
  if ($Binary -ne $installedBinary) { Copy-Item -LiteralPath $Binary -Destination $installedBinary -Force }
  if ($FullAdmin) {
    Write-Warning 'Installing owner-approved Full Admin service as LocalSystem.'
    & (Join-Path $destination 'opengate.exe') --data-dir $data service install --system --full-admin
  } else {
    & (Join-Path $destination 'opengate.exe') --data-dir $data service install --system
  }
  if ($LASTEXITCODE -ne 0) { throw "OpenGate service installation failed ($LASTEXITCODE)" }
  Remove-Item -LiteralPath $backup -ErrorAction SilentlyContinue
} catch {
  if (Test-Path -LiteralPath $backup) {
    Stop-Service OpenGate -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $backup -Destination $installedBinary -Force
    if ($wasRunning) { Start-Service OpenGate }
  }
  throw
}
