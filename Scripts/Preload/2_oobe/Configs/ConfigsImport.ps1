$ConfirmPreference = "None"
$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

Start-Transcript -Path "C:\Windows\MDT\ConfigsImport.log"

function FirefoxConfig { 
    param (
        $SourcePolicy = "\\MDTOMI-WS1\DeploymentShare$\Scripts\policies.json", #policies.json kann am einfachsten mit dem Firefox Add-on "Enterprise Policy Generator" erstellt werden
        $firefoxPath = "C:\Program Files\Mozilla Firefox"
    )
    Write-Host "Firefox wird konfiguriert..." 
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
    Write-Host "Konfiguration abgeschlossen"
}
FirefoxConfig
function EdgeConfig {
    param (
        $rec = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge\Recommended'
    )
    Write-Host "Edge wird konfiguriert..."
    # Registry-Pfad anlegen
    if (-not (Test-Path $rec)) { 
        New-Item $rec -Force | Out-Null
        Write-Host "Registry-Pfad erstellt: $rec"
    }

    # Startseite
    New-ItemProperty -Path $rec -Name HomepageLocation -PropertyType String -Value 'https://www.google.ch' -Force | Out-Null
    Write-Host "Startseite wurde gesetzt (reg)"

    # Beim Start bestimmte Seite öffnen
    New-ItemProperty -Path $rec -Name RestoreOnStartup -PropertyType DWord -Value 4 -Force | Out-Null
    Write-Host "Restore on Startup wurde konfiguriert (reg)"

    # Startup-URLs
    New-ItemProperty -Path $rec -Name RestoreOnStartupURLs -PropertyType MultiString -Value @('https://www.google.ch') -Force | Out-Null
    Write-Host "Restore on Startup URLs wurden konfiguriert (reg)"

    Write-Host "Edge-Konfiguration abgeschlossen"
}
#EdgeConfig
Stop-Transcript