$ConfirmPreference = "None"
$ErrorActionPreference = "Continue"

$logFolder = "C:\Windows\MDT"
$log = "$logFolder\OOBEstartlayout.log"
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory | Out-Null
}

$hostname = $env:COMPUTERNAME
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$compInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$hersteller = $compInfo.Manufacturer
$modell = $compInfo.Model

"--- MDT OOBE Import default Startlayout Log $(Get-Date) | $hostname --- | $os --- | $hersteller $modell ---" | Out-File -FilePath $log -Encoding utf8 -Append

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

# --------------------------------------------------------------------------

# Skript an sich:
Log-Command 'xcopy "\\MDTOMI-WS1\DeploymentShare$\Scripts\start.bin" "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\" /y'
Log-Command 'dism /Online /Import-DefaultAppAssociations:\\MDTOMI-WS1\DeploymentShare$\Scripts\DefaultApps.xml'

"--- Skript beendet: $(Get-Date) | $hostname --- | $os --- | $hersteller $modell ---" | Out-File -FilePath $log -Encoding utf8 -Append