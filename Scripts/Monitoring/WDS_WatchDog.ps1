# --- Einstellungen ---
$ServiceName    = 'WDSServer'
$LogFile        = 'C:\Logs\WDS-Watchdog.log'
$CheckPxePort   = $true
$PxePort        = 4011
$RestartTimeoutSec = 60

function Write-Log([string]$msg) {
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $dir = Split-Path $LogFile
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Add-Content -Path $LogFile -Value "$stamp  $msg"
}

try { $svc = Get-Service -Name $ServiceName -ErrorAction Stop }
catch { Write-Log "ERROR: Dienst '$ServiceName' existiert nicht. $_"; exit 2 }

if ($svc.Status -ne 'Running') {
    Write-Log "WARN: Dienststatus = $($svc.Status). Versuche Start..."
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        (Get-Service $ServiceName).WaitForStatus('Running','00:00:30')
        Write-Log "OK: Dienst wurde gestartet."
        exit 0
    } catch {
        Write-Log "ERROR: Start fehlgeschlagen. Versuche Restart... $_"
        try {
            Restart-Service -Name $ServiceName -Force -ErrorAction Stop
            (Get-Service $ServiceName).WaitForStatus('Running','00:00:30')
            Write-Log "OK: Dienst wurde neu gestartet."
            exit 0
        } catch {
            Write-Log "CRIT: Neustart fehlgeschlagen. Warte $RestartTimeoutSec s und versuche Systemneustart..."
            Start-Sleep -Seconds $RestartTimeoutSec
            try { Restart-Computer -Force } catch { Write-Log "CRIT: Systemneustart konnte nicht ausgelöst werden. $_"; exit 1 }
        }
    }
}

if ($CheckPxePort) {
    $bound = $false
    try { $bound = [bool](Get-NetUDPEndpoint -LocalPort $PxePort -ErrorAction SilentlyContinue) } catch {}
    if (-not $bound) {
        Write-Log "WARN: Dienst läuft, aber UDP $PxePort ist nicht gebunden. Neustart wird versucht..."
        try { Restart-Service -Name $ServiceName -Force -ErrorAction Stop; Write-Log "OK: Dienst wegen fehlender Portbindung neu gestartet."; exit 0 }
        catch { Write-Log "ERROR: Neustart wegen Portbindung fehlgeschlagen. $_"; exit 1 }
    }
}

Write-Log "OK: Dienst läuft normal."
exit 0