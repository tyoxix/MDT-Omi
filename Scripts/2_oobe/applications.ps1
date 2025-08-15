$ConfirmPreference = "None"
$ErrorActionPreference = "Continue"

$env:PATH += ";C:\ProgramData\chocolatey\bin" # Muss bei OOBE definiert werden

# Transcript in OOBE nicht möglich, deshalb individuelles loggen.
$logFolder = "C:\Windows\MDT"
$log = "$logFolder\OOBEapplications.log"
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory | Out-Null
}

$hostname = $env:COMPUTERNAME
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$compInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$hersteller = $compInfo.Manufacturer
$modell = $compInfo.Model

"--- MDT OOBE Application Install Log $(Get-Date) | $hostname --- | $os --- | $hersteller $modell ---" | Out-File -FilePath $log -Encoding utf8 -Append

function Log-Command {
    param (
        [string]$command
    )
    "`n>>> $command >>> $(Get-Date)" | Out-File -FilePath $log -Encoding utf8 -Append
    try {
        Invoke-Expression "$command 2>&1" | Out-File -FilePath $log -Encoding utf8 -Append
    } catch {
        "FEHLER bei Befehl: $command" | Out-File -FilePath $log -Encoding utf8 -Append
        $_ | Out-String | Out-File -FilePath $log -Encoding utf8 -Append
    }
}

#--------------------------------------------------------------------------
# WICHTIG!!: Jegliche Software, die als MSStore-App installiert wird, muss im Skript WindowsDeployment_Universal.ps1 hinterlegt werden,
# da MSStore-Apps nur für den aktiven Benutzer installiert werden (in diesem Schritt ist das noch Administrator).
# Ob es sich bei einer installation um ein Programm oder eine App handelt sehr ihr, wenn ihr in cmd nach dem Program sucht: winget search "Name oder ID"
# => Wenn als Quelle winget steht, ist es ein Programm. Wenn msstore steht, eine MSStore-App.
# => Chocolatey installationen sind immer Programme

# Deshalb hier Standardprogramme mit Chocolatey installieren und Herstellerabhängige Software in WindowsDeployment_Universal.ps1

# Alle Geräte Standardprogramme //Da Winget im OOBE nicht funktioniert zwingend mit chocolatey installieren!
Log-Command 'choco install adobereader -y'
Log-Command 'choco install firefox -y'
Log-Command 'choco install vlc -y'
Log-Command 'choco install 7zip -y'

"--- Skript beendet: $(Get-Date) | $hostname --- | $os --- | $hersteller $modell ---" | Out-File -FilePath $log -Encoding utf8 -Append