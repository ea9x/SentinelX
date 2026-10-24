param([string]$UserId=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
$ErrorActionPreference='Stop'
$taskName='SentinelX Local Startup'
$taskLauncher=Join-Path $PSScriptRoot 'start_local.ps1'
if (-not (Test-Path -LiteralPath $taskLauncher -PathType Leaf)) { throw 'Local launcher is missing.' }
$taskExisting=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($taskExisting -and ($taskExisting.Actions.Arguments -notlike ('*'+$taskLauncher+'*'))) { throw 'An unrelated startup task already uses this name.' }
$taskLegacy=@('SentinelX - Backend','SentinelX - Frontend','SentinelX - OWASP ZAP')
$taskFound=@()
foreach ($taskOldName in $taskLegacy) {
    $taskOld=Get-ScheduledTask -TaskName $taskOldName -ErrorAction SilentlyContinue
    if (-not $taskOld) { continue }
    $taskCommands=@($taskOld.Actions | ForEach-Object {
        $taskArgument=$_.Arguments
        if ($taskArgument -match '-EncodedCommand\s+(\S+)') { [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1])) } else { $taskArgument }
    }) -join ' '
    $taskCommands=$taskCommands.Replace('\\','\')
    if ($taskCommands -notlike ('*'+$PSScriptRoot+'*')) { throw "Legacy task belongs to another project: $taskOldName" }
    $taskFound+=$taskOld
}
$taskBackup=Join-Path $PSScriptRoot ('.local\startup-backups\'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $taskBackup -Force | Out-Null
@($taskFound)+@($taskExisting | Where-Object { $_ }) | ForEach-Object {
    Export-ScheduledTask -TaskName $_.TaskName | Set-Content -LiteralPath (Join-Path $taskBackup ($_.TaskName+'.xml')) -Encoding Unicode
}
$taskAction=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$taskLauncher+'" -Quiet') -WorkingDirectory $PSScriptRoot
$taskTrigger=New-ScheduledTaskTrigger -AtLogOn -User $UserId
$taskPrincipal=New-ScheduledTaskPrincipal -UserId $UserId -LogonType Interactive -RunLevel Limited
$taskSettings=New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Description 'Start local SentinelX services after this user signs into Windows.' -Force | Out-Null
foreach ($taskOld in $taskFound) {
    Disable-ScheduledTask -TaskName $taskOld.TaskName -ErrorAction Stop | Out-Null
    if ((Get-ScheduledTask -TaskName $taskOld.TaskName).Settings.Enabled) { throw "Legacy startup task was not disabled: $($taskOld.TaskName). Run registration from an administrator PowerShell." }
}
[pscustomobject]@{task=$taskName;user=$UserId;backup=$taskBackup;disabled_legacy=@($taskFound.TaskName)} | ConvertTo-Json
