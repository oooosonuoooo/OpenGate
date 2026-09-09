param(
    [ValidateSet('Host','Controller','Both')]
    [string]$Mode = 'Host',
    [int]$Port = 44344
)
$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host 'OpenGate setup needs Administrator rights to install Python/OpenSSH and startup tasks. Requesting elevation...'
    $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Mode $Mode -Port $Port"
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argLine
    exit
}

function Find-Python {
    $roots = @('C:\Program Files', 'C:\Program Files (x86)')
    foreach ($root in $roots) {
        if (Test-Path $root) {
            $found = Get-ChildItem -Path $root -Filter python.exe -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match 'Python3' } |
                Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike '*WindowsApps*') { return $cmd.Source }
    return $null
}

$Python = Find-Python
if (-not $Python) {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw 'Python 3.10+ is required and winget is not available. Install Python system-wide, then run this installer again.'
    }
    Write-Host 'Installing Python 3 system-wide...'
    winget install --id Python.Python.3.13 -e --scope machine --accept-package-agreements --accept-source-agreements --silent
    $Python = Find-Python
    if (-not $Python) { throw 'Python installation completed but python.exe could not be located.' }
}

$InstallDir = Join-Path $env:ProgramFiles 'OpenGate'
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$Source = Join-Path (Split-Path $PSScriptRoot -Parent) 'opengate.py'
Copy-Item $Source (Join-Path $InstallDir 'opengate.py') -Force

$Cmd = "@echo off`r`n`"$Python`" `"$InstallDir\opengate.py`" %*`r`n"
Set-Content -Path (Join-Path $InstallDir 'opengate.cmd') -Value $Cmd -Encoding ASCII
$machinePath = [Environment]::GetEnvironmentVariable('Path','Machine')
if (-not $machinePath) { $machinePath = '' }
if (($machinePath -split ';') -notcontains $InstallDir) {
    $newPath = ($machinePath.TrimEnd(';') + ';' + $InstallDir).TrimStart(';')
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
}

if ($Mode -eq 'Host' -or $Mode -eq 'Both') {
    $server = Get-WindowsCapability -Online | Where-Object Name -Like 'OpenSSH.Server*' | Select-Object -First 1
    if (-not $server) { throw 'Windows OpenSSH Server capability was not found.' }
    if ($server.State -ne 'Installed') {
        Write-Host 'Installing Windows OpenSSH Server...'
        Add-WindowsCapability -Online -Name $server.Name | Out-Null
    }
    Set-Service -Name sshd -StartupType Automatic
    Start-Service sshd

    if (-not (Get-NetFirewallRule -DisplayName 'OpenGate SSH Transport' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'OpenGate SSH Transport' -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
    }

    $TaskName = 'OpenGate Host'
    $Action = New-ScheduledTaskAction -Execute $Python -Argument "`"$InstallDir\opengate.py`" host --system --bind 0.0.0.0:$Port"
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
}

if ($Mode -eq 'Controller' -or $Mode -eq 'Both') {
    $client = Get-WindowsCapability -Online | Where-Object Name -Like 'OpenSSH.Client*' | Select-Object -First 1
    if ($client -and $client.State -ne 'Installed') {
        Write-Host 'Installing Windows OpenSSH Client...'
        Add-WindowsCapability -Online -Name $client.Name | Out-Null
    }
}

Write-Host ''
Write-Host 'OpenGate installation complete.'
Write-Host 'Open a NEW terminal so the opengate command is on PATH.'
if ($Mode -eq 'Host' -or $Mode -eq 'Both') {
    Write-Host 'The host background task starts automatically at Windows startup.'
    Write-Host "Generate a single-use pairing token from an Administrator terminal:"
    Write-Host "  opengate token --system --advertise <reachable-ip-or-dns>:$Port"
}
if ($Mode -eq 'Controller' -or $Mode -eq 'Both') {
    Write-Host "Pair/connect with: opengate connect --token '<TOKEN>'"
}
