param(
    [Parameter(Mandatory=$true)][string]$Device,
    [int]$LocalPort = 2222
)
$ErrorActionPreference = 'Stop'
$OpenGate = (Get-Command opengate.cmd -ErrorAction Stop).Source
$TaskName = "OpenGate Controller - $Device"
$Arguments = "/c `"`"$OpenGate`" connect --device `"$Device`" --listen 127.0.0.1:$LocalPort --retry-seconds 300`""
$Action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $Arguments
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Controller auto-start enabled. Local SSH endpoint: 127.0.0.1:$LocalPort"
