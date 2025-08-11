$ConfirmPreference = "None"
$ErrorActionPreference = "Continue"

Start-Transcript -Path "C:\Windows\MDT\import_configs.log"

Write-Host "Firefox wird konfiguriert..." 
$SourcePolicy = "\\MDTOMI-WS1\DeploymentShare$\Scripts\policies.json"
#Zielpfade
$firefoxPath = "C:\Program Files\Mozilla Firefox"
$distributionPath = Join-Path $firefoxPath "distribution"
$destFile = Join-Path $distributionPath "policies.json"
#Quelle prüfen
if (-not (Test-Path -Path $SourcePolicy -PathType Leaf)) {
    Write-Host "FEHLER: Quelle nicht gefunden: $SourcePolicy"
    exit 1
}
#Zielordner erstellen, falls nicht vorhanden
if (-not (Test-Path -Path $distributionPath)) {
    New-Item -Path $distributionPath -ItemType Directory -Force | Out-Null
    Write-Host "Ordner 'distribution' erstellt: $distributionPath"
}
#Datei kopieren
Copy-Item -Path $SourcePolicy -Destination $destFile -Force
Write-Host "policies.json kopiert nach: $destFile"

Stop-Transcript