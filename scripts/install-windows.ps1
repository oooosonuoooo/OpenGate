[CmdletBinding()]
param([string]$Binary = '.\target\release\opengate.exe', [switch]$FullAdmin)
if (-not (Test-Path $Binary -PathType Leaf)) { throw "Binary not found: $Binary" }
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'Requesting administrator approval to install the OpenGate service...'
  Start-Process powershell -Verb RunAs -Wait -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -Binary `"$Binary`" $($FullAdmin ? '-FullAdmin' : '')"
  exit $LASTEXITCODE
}
$destination = Join-Path $env:ProgramFiles 'OpenGate'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
Copy-Item -Force $Binary (Join-Path $destination 'opengate.exe')
$data = Join-Path $env:ProgramData 'OpenGate'
if ($FullAdmin) { Write-Warning 'Full Admin requires allow_admin = true in the existing service config. It will not be enabled automatically.' }
& (Join-Path $destination 'opengate.exe') --data-dir $data service install --system $(if ($FullAdmin) { '--full-admin' })
if ($LASTEXITCODE -ne 0) { throw "OpenGate service installation failed ($LASTEXITCODE)" }
