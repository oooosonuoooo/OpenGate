[CmdletBinding()]
param([string]$Binary = '.\target\release\opengate.exe', [switch]$FullAdmin)
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
Copy-Item -Force $Binary (Join-Path $destination 'opengate.exe')
$data = Join-Path $env:ProgramData 'OpenGate'
if ($FullAdmin) {
  $config = Join-Path $data 'config.toml'
  if (-not (Test-Path $config -PathType Leaf) -or -not (Select-String -Path $config -Pattern '^\s*allow_admin\s*=\s*true\s*(?:#.*)?$' -Quiet)) {
    throw "Full Admin requires the existing owner configuration $config to contain allow_admin = true. It is never enabled automatically."
  }
  Write-Warning 'Installing owner-approved Full Admin service as LocalSystem.'
  & (Join-Path $destination 'opengate.exe') --data-dir $data service install --system --full-admin
} else {
  & (Join-Path $destination 'opengate.exe') --data-dir $data service install --system
}
if ($LASTEXITCODE -ne 0) { throw "OpenGate service installation failed ($LASTEXITCODE)" }
