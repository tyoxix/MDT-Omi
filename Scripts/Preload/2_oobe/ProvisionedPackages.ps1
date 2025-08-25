$ConfirmPreference = "None"
$ErrorActionPreference = "Continue"

#Transcript in OOBE nicht möglich, deshalb individuelles loggen.
$logFolder = "C:\Windows\MDT"
$log = "$logFolder\OOBEprovisionedpackages.log"
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory | Out-Null
}

$hostname = $env:COMPUTERNAME
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$compInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$hersteller = $compInfo.Manufacturer
$modell = $compInfo.Model

"--- MDT OOBE Package Provisioning Log $(Get-Date) | $hostname --- | $os --- | $hersteller $modell ---" | Out-File -FilePath $log -Encoding utf8 -Append

function Log-AppRemove {
    param(
        [string]$command,
        [string]$infoText = ""
    )
    "`n>>> $command >>> $(Get-Date)" | Out-File -FilePath $log -Encoding utf8 -Append
    if ($infoText) {
        "$infoText" | Out-File -FilePath $log -Encoding utf8 -Append
    }
    try {
        Invoke-Expression "$command 2>&1" | Out-File -FilePath $log -Encoding utf8 -Append
    } catch {
        "FEHLER bei Befehl: $command" | Out-File -FilePath $log -Encoding utf8 -Append
        $_ | Out-String | Out-File -FilePath $log -Encoding utf8 -Append
    }
}

# --------------------------------------------------------------------------

# App-Pakete-Liste //Hier neue Apps hinzufügen
$appxPackages = @(
    "Microsoft.3DBuilder",
    "Microsoft.AppConnector",
    "Microsoft.BingFinance",
    "Microsoft.BingNews",
    "Microsoft.BingSports",
    "Microsoft.BingTranslator",
    "Microsoft.BingWeather",
    "Microsoft.CommsPhone",
    "Microsoft.ConnectivityStore",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftPowerBIForWindows",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MicrosoftStickyNotes",
    "Microsoft.MinecraftUWP",
    "Microsoft.MSPaint",
    "Microsoft.NetworkSpeedTest",
    "Microsoft.Office.OneNote",
    "Microsoft.Office.Sway",
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.Print3D",
    "Microsoft.RemoteDesktop",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsCamera",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsPhone",
    "Microsoft.WindowsSoundRecorder",
    "2414FC7A.Viber",
    "41038Axilesoft.ACGMediaPlayer",
    "46928bounde.EclipseManager",
    "4DF9E0F8.Netflix",
    "64885BlueEdge.OneCalendar",
    "7EE7776C.LinkedInforWindows",
    "828B5831.HiddenCityMysteryofShadows",
    "89006A2E.AutodeskSketchBook",
    "9E2F88E3.Twitter",
    "A278AB0D.DisneyMagicKingdoms",
    "A278AB0D.MarchofEmpires",
    "ActiproSoftwareLLC.562882FEEB491",
    "AdobeSystemsIncorporated.AdobePhotoshopExpress",
    "CAF9E577.Plex",
    "D52A8D61.FarmVille2CountryEscape",
    "D5EA27B7.Duolingo-LearnLanguagesforFree",
    "DB6EA5DB.CyberLinkMediaSuiteEssentials",
    "DolbyLaboratories.DolbyAccess",
    "Drawboard.DrawboardPDF",
    "Facebook.Facebook",
    "flaregamesGmbH.RoyalRevolt2",
    "GAMELOFTSA.Asphalt8Airborne",
    "KeeperSecurityInc.Keeper",
    "king.com.BubbleWitch3Saga",
    "king.com.CandyCrushSodaSaga",
    "PandoraMediaInc.29680B314EFC2",
    "SpotifyAB.SpotifyMusic",
    "WinZipComputing.WinZipUniversal",
    "XINGAG.XING",
    "Microsoft.549981C3F5F10",
    "Microsoft.OutlookForWindows",
    "MicrosoftTeams",
    "Microsoft.Teams",
    "MSTeams",
    "Microsoft.Todos",
    "Microsoft.LinkedIn"
)

# Für bestehende Benutzer entfernen
foreach ($pkg in $appxPackages) {
    Log-AppRemove "Get-AppxPackage -Name `"$pkg`" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue" "Entferne App (Benutzer): $pkg"
}

# Für neue Benutzer (provisioned packages) entfernen
foreach ($pkg in $appxPackages) {
    Log-AppRemove "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq `"$pkg`" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue" "Entferne App (Provisioned): $pkg"
}

# Für Apps mit Wildcards (Benutzer & Provisioned)
$wildcards = @("*solitairecollection*", "*WebExperience*", "*xbox*")
foreach ($wild in $wildcards) {
    Log-AppRemove "Get-AppxPackage -AllUsers $wild | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue" "Entferne Wildcard-App: $wild"
    Log-AppRemove "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like `"$wild`" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue" "Entferne Provisioned Wildcard-App: $wild"
}

"--- Skript beendet: $(Get-Date) | $hostname --- | $os --- | $hersteller $modell ---" | Out-File -FilePath $log -Encoding utf8 -Append