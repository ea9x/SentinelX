param([ValidateSet('start','backup','verify')][string]$Action='start', [string]$Archive, [switch]$Quiet)
$ErrorActionPreference='Stop'
$taskProjectRoot=$PSScriptRoot
$taskLocal=Join-Path $taskProjectRoot '.local'
New-Item -ItemType Directory -Path $taskLocal -Force | Out-Null
Push-Location (Join-Path $taskProjectRoot 'backend')
try {
    $taskPython=Join-Path $taskProjectRoot 'backend\venv\Scripts\python.exe'
    if ($Action -eq 'verify') {
        if (-not $Archive) { throw 'Provide an encrypted .sxbackup archive to verify.' }
        & $taskPython -B maintenance.py verify $Archive *>> (Join-Path $taskLocal 'maintenance.log')
    } else {
        & $taskPython -B maintenance.py $Action *>> (Join-Path $taskLocal 'maintenance.log')
    }
    if ($LASTEXITCODE -ne 0) { throw 'Maintenance command failed. See .local\maintenance.log.' }
} finally { Pop-Location }

if ($Action -eq 'start') {
    $taskReady = $false
    for ($taskAttempt=0; $taskAttempt -lt 20; $taskAttempt++) {
        try {
            $taskBackend=Invoke-RestMethod 'http://127.0.0.1:5000/' -TimeoutSec 3
            $taskPage=Invoke-WebRequest 'http://127.0.0.1:8088/login' -UseBasicParsing -TimeoutSec 3
            if ($taskBackend.status -eq 'OK' -and $taskPage.StatusCode -eq 200) { $taskReady=$true; break }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    if (-not $taskReady) { throw 'SentinelX did not become ready. See .local service logs.' }
    if (-not $Quiet) { Start-Process 'http://127.0.0.1:8088/login' }
}
