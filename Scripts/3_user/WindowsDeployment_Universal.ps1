<#
Autor: Tobias Hösli / Omikron Data AG
Letzte Änderungen: 18.08.2025, th

https://github.com/tyoxix/MDT-Omi/wiki/MDT-Omikron-WIKI
#>

#--------------------------------------------------------------------------

#Script mit Adminrechten neustarten
Function Adminneustart {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}
Adminneustart

#Preferences
$ConfirmPreference = "None"
$ErrorActionPreference = "Stop"
$VerbosePreference = "SilentlyContinue"

#Try/Catch Error Log für Desktop
Function Write-ErrorLog {
    param([string]$Message)
    $ErrorLogFile = "$env:USERPROFILE\Desktop\preload_errors.log"
    # Prüfen, ob Datei existiert, falls nicht, Hinweis schreiben
    if (!(Test-Path $ErrorLogFile)) {
        Add-Content -Path $ErrorLogFile -Value "Hinweis: Diese Datei enthält alle Fehler, die während des Ausrollens des Preloads aufgetreten sind.`nSollte der untenstehende Fehler wiederholt auftreten, erstelle bitte ein Ticket im Ticketsystem (helpdesk.omikron.ch) in der Gruppe MDT. Füge eine kurze Beschreibung des Problems, die Datei preload_errors.log sowie die LOG-Dateien aus C:\Windows\MDT bei.`r`n"
    }
    $timestamp = Get-Date -Format 'dd-MM-yyyy HH:mm:ss'
    Add-Content -Path $ErrorLogFile -Value "$timestamp $Message"
}

#Errorlog für logdateien
$logPath = "C:\Windows\MDT\WindowsDeployment.log"
$logFolder = Split-Path $logPath
try {
    if (-not (Test-Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory | Out-Null
    }
}
catch { Write-ErrorLog $_.Exception.Message }

clear
Start-Transcript -Path $logPath

#--------------------------------------------------------------------------

#Windows Festplatte zu "System" umbenennen
Function Festplatteumbenennen {
    try {
        Write-Output "Windows Festplatte wird umbenannt..."
        Set-Volume -DriveLetter C -NewFileSystemLabel "System"
    }
    catch { Write-ErrorLog "Function Festplatteumbenennen: " + $_.Exception.Message }
}
Festplatteumbenennen

#Anzeigen von "Dieser PC" auf Desktop
Function DieserPCaufDesktop {
    try {
        Write-Output "Dieser PC wird auf den Desktop hinzugefügt..."
        If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
        If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
    }
    catch { Write-ErrorLog "Function DieserPCaufDesktop: " + $_.Exception.Message }
}
DieserPCaufDesktop

#Anzeigen des Benutzerordners auf Dektop
Function BenutzerordneraufDesktop {
    try {
        Write-Output "Benutzerordner wird auf den Desktop hinzugefügt..."
        If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
        If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
    }
    catch { Write-ErrorLog "Function BenutzerordneraufDesktop: " + $_.Exception.Message }
}
BenutzerordneraufDesktop

#Kleine Symbole in Systemsteuerung festlegen
Function SystemsteuerungKleineSymbole {
    try {
        Write-Output "Kleine Symbole werden in Systemsteuerung festgelegt..."
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1
    }
    catch { Write-ErrorLog "Function SystemsteuerungKleineSymbole: " + $_.Exception.Message }
}
SystemsteuerungKleineSymbole

#SmartScreen deaktivieren
Function Smartscreendeaktivieren {
    try {
        Write-Output "SmartScreen wird deaktiviert..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
    }
    catch { Write-ErrorLog "Function Smartscreendeaktivieren: " + $_.Exception.Message }
}
Smartscreendeaktivieren

#Windows Darkmode aktivieren
Function DarkModeAktivieren {
    try {
        Write-Output "Windows Dark Mode wird aktiviert..."
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
    }
    catch { Write-ErrorLog "Function DarkModeAktivieren: " + $_.Exception.Message }
}
DarkModeAktivieren

#Explorer für "Dieser PC" Öffnen
Function ExplorerfürDieserPC {
    try {
        Write-Output "Setze Explorer öffnen für Dieser PC..."
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 -Force | Out-Null
    }
    catch { Write-ErrorLog "Function ExplorerfürDieserPC: " + $_.Exception.Message }
}
ExplorerfürDieserPC

#Französisch (Schweiz) & Deutsch (Deutschland) löschen
Function löschetastaturen {
    try {
        Write-Output "Französisch (Schweiz) Tastaturlayout wird entfernt..."
        $langs = Get-WinUserLanguageList
        Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "fr-CH"}) -Force  | Out-Null
        Write-Output "Deutsch (Deutschland) Tastaturlayout wird entfernt..."
        $langs = Get-WinUserLanguageList
        Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "de-DE"}) -Force  | Out-Null
    }
    catch { Write-ErrorLog "Function löschetastaturen: " + $_.Exception.Message }
}
löschetastaturen

#Löschen von "Fax" und "Microsoft XPS Document Writer" Druckern 
Function LöscheDrucker {
    try {
        Write-Output "Fax Drucker wird entfernt..."
        Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue | Out-Null
        Write-Output "Microsoft XPS Document Writer Drucker wird entfernt..."
        Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
    }
    catch { Write-ErrorLog "Function LöscheDrucker: " + $_.Exception.Message }
}
LöscheDrucker

#Synchronisierung der Uhrzeit
function Uhrzeit {
    try {
        Write-Output "Uhrzeit wird synchronisiert..."
        $service = Get-Service w32time -ErrorAction Stop
        if ($service.Status -eq "Running") {
            $output = & net stop w32time
            if ($output -match "Fehler|Error|Failed") { throw ($output -join "`n") }
        }
        if ((Get-Service w32time).Status -ne "Running") {
            $output = & net start w32time
            if ($output -match "Fehler|Error|Failed") { throw ($output -join "`n") }
        }
        $output = & w32tm /config /manualpeerlist:time.windows.com,0x8 /syncfromflags:MANUAL
        if ($output -match "Fehler|Error|Failed") { throw ($output -join "`n") }

        $output = & w32tm /config /update
        if ($output -match "Fehler|Error|Failed") { throw ($output -join "`n") }

        $output = & w32tm /resync
        if ($output -match "Fehler|Error|Failed") { throw ($output -join "`n") }              
    }
    catch {
        Write-ErrorLog "function Uhrzeit: " + $_.Exception.Message
    }
}
Uhrzeit

#Action Center deaktivieren (App Icons) / Benachrichtigungen anzeigen
Function ActionCenterKonfigurieren {
    try {
        Write-Output "Action Center wird konfiguriert... "
        If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_GLEAM_ENABLED" -Type DWord -Value 0 -Force | Out-Null
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_BADGE_ENABLED" -Type DWord -Value 0 -Force | Out-Null
    }
    catch {
        Write-ErrorLog "Function ActionCenterKonfigurieren: " + $_.Exception.Message
    }
}
ActionCenterKonfigurieren

#Explorer Datenschutzoptionen
Function ExplorerDatenschutzKonfigurieren {
    try {
        Write-Output "Explorer Datenschutzeinstellungen werden konfiguriert..."
        If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0 -Force | Out-Null
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 -Force | Out-Null
    }
    catch {
        Write-ErrorLog "Function ExplorerDatenschutzKonfigurieren " + $_.Exception.Message
    }
}
ExplorerDatenschutzKonfigurieren

#Dateiendungen anzeigen
Function DateiendungenAktivieren {
    try {
        Write-Output "Dateiendungen werden aktiviert..."
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord -Force | Out-Null
    }
    catch {
        Write-ErrorLog "Function DateiendungenAktivieren: " + $_.Exception.Message
    }
}
DateiendungenAktivieren

#Suchleiste als Lupe anzeigen
Function SuchleisteAlsLupeAnzeigen {
    try {
        Write-Output "Suchleiste als Lupe anzeigen wird aktiviert..."
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1 -Force | Out-Null
    }
    catch {
        Write-ErrorLog "Function SuchleisteAlsLupeAnzeigen: " + $_.Exception.Message
    }
}
SuchleisteAlsLupeAnzeigen

#NumLock dauerhaft aktivieren
Function NumLockDauerhaftAktivieren {
    try {
        Write-Host "Aktiviere NumLock dauerhaft..."
        If (!(Test-Path "HKU:")) {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
        }
        Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650 -Force | Out-Null
        Add-Type -AssemblyName System.Windows.Forms
        If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
            $wsh = New-Object -ComObject WScript.Shell
            $wsh.SendKeys('{NUMLOCK}')
        }
    }
    catch {
        Write-ErrorLog "Function NumLockDauerhaftAktivieren: " + $_.Exception.Message
    }
}
NumLockDauerhaftAktivieren

#Altes Kontextmenü / Recktsklick aktivieren
Function AltesKontextmenueAktivieren {
    try {
        Write-Output "Altes Windows Menü wird aktiviert..."
        New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
        Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -Value "" -Force | Out-Null
    }
    catch {
        Write-ErrorLog "Function AltesKontextmenueAktivieren: " + $_.Exception.Message
    }
}
AltesKontextmenueAktivieren

#Chat von Taskbar lösen
Function ChatVonTaskleisteEntfernen {
    try {
        Write-Output "Chat wird von der Taskleiste entfernt..."
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type DWord -Value 0 | Out-Null
    }
    catch {
        Write-ErrorLog "Function ChatVonTaskleisteEntfernen: " + $_.Exception.Message
    }
}
ChatVonTaskleisteEntfernen

#Bing-Websuche deaktivieren
Function WebsucheDeaktivieren { 
    try {
        Write-Output "Bing-Websuche in der Windows-Suche wird deaktiviert..."
        If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
            New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Type DWord -Value 1
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    }
    catch {
        Write-ErrorLog "Function WebsucheDeaktivieren: " + $_.Exception.Message
    }
}
WebsucheDeaktivieren

#Detailed BSOD aktivieren
Function DetailedBsodAktivieren {
    try {
        Write-Output "Detailed (klassischer) Bluescreen wird aktiviert..."
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
        If (!(Test-Path $regPath)) {
            New-Item -Path $regPath | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "DisplayParameters" -Type DWord -Value 1
    }
    catch {
        Write-ErrorLog "Function DetailedBsodAktivieren: " + $_.Exception.Message
    }
}
DetailedBsodAktivieren

#Starteinstellungen anpassen
Function Startmenu {
    try {
        #Meistverwendete Apps anzeigen
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackFrequent" -Type DWord -Value 1
        #Empfehlungen für Tipps, Verknüpfungen, neue Apps deaktivieren
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Type DWord -Value 0
        #Kontobezogene Benachrichtigungen deaktivieren
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_AccountNotifications" -Type DWord -Value 0
    }
    catch {
        Write-ErrorLog "Function Startmenu: " + $_.Exception.Message
    }
}
Startmenu

#Energiesparplan anpassen
Function Energiesparplan {
    try {
        Write-Output "Energieeinstellungen werden angepasst..."
        # Bildschirm ausschalten nach 20 Minuten (Netz- und Akkubetrieb)
        powercfg /change monitor-timeout-ac 20
        powercfg /change monitor-timeout-dc 20
        # Energiesparmodus (Sleep) NIE (Netz- und Akkubetrieb)
        powercfg /change standby-timeout-ac 0
        powercfg /change standby-timeout-dc 0
        # Festplatte ausschalten NIE (Netz- und Akkubetrieb)
        powercfg /change disk-timeout-ac 0
        powercfg /change disk-timeout-dc 0
    }
    catch {
        Write-ErrorLog "Function Energiesparplan: " + $_.Exception.Message
    }
}
Energiesparplan

#Richtige Festplatte als "Daten" formatieren 
Function FindDatadrive {
    	try {
		$OSDiskNumber = Get-Disk | Where-Object -FilterScript {$_.BusType -ne "USB"} | Sort-Object -Property "Total Size" -Descending | Select-Object -Last 1 | Select-Object -ExpandProperty Number
		$seconddisk = Get-Disk | Where-Object -FilterScript {$_.BusType -ne "USB"} | Sort-Object -Property "Total Size" -Descending | Select-Object -First 1 | Select-Object -ExpandProperty Number
		if($OSDiskNumber -ne $seconddisk){
			Initialize-Disk -Number $seconddisk | Out-Null
			new-partition -disknumber $seconddisk -usemaximumsize | format-volume -filesystem NTFS -newfilesystemlabel Daten | Out-Null
			Get-WmiObject -Class Win32_volume -Filter 'DriveType=5' | Select-Object -First 1 | Set-WmiInstance -Arguments @{DriveLetter='E:'} | Out-Null
			Get-CimInstance -classname Win32_volume | ?{$_.Label -eq 'Daten'} | Set-CimInstance -Arguments @{Driveletter="D:"} | Out-Null
			Write-Output "Sekundäre Festplatte wurde als 'Daten' formatiert"
		}
	}
	catch { 
		Write-ErrorLog "Function FindDatadrive: Die Datenfestplatte wurde bereits initialisiert. Zur Vermeidung von Datenverlust wurde keine Formatierung ausgeführt. Bestätige den richtigen Datenträger und formatiere ihn nur bei Gewissheit!" + $_.Exception.Message 
		}
}
FindDatadrive

#Edge Debloat
Function EdgeDebloat{
    try {
        Write-Host "Edge wird deabloated..."
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "CreateDesktopShortcutDefault" -Type DWord -Value 0
        $edgePolicies = @(
            @{Name="PersonalizationReportingEnabled"; Value=0},
            @{Name="ShowRecommendationsEnabled"; Value=0},
            @{Name="HideFirstRunExperience"; Value=1},
            @{Name="UserFeedbackAllowed"; Value=0},
            @{Name="ConfigureDoNotTrack"; Value=1},
            @{Name="AlternateErrorPagesEnabled"; Value=0},
            @{Name="EdgeCollectionsEnabled"; Value=0},
            @{Name="EdgeShoppingAssistantEnabled"; Value=0},
            @{Name="MicrosoftEdgeInsiderPromotionEnabled"; Value=0},
            @{Name="ShowMicrosoftRewards"; Value=0},
            @{Name="WebWidgetAllowed"; Value=0},
            @{Name="DiagnosticData"; Value=0},
            @{Name="EdgeAssetDeliveryServiceEnabled"; Value=0},
            @{Name="CryptoWalletEnabled"; Value=0},
            @{Name="WalletDonationEnabled"; Value=0}
        )
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
        foreach ($entry in $edgePolicies) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name $entry.Name -Type DWord -Value $entry.Value
        }
    }
    catch { Write-ErrorLog "Function EdgeDebloat: " + $_.Exception.Message }
} 
EdgeDebloat

#Media Player deaktivieren
Function MediaPlayerDeaktivieren {
    try {
        Write-Host "Windows Media Player wird deaktiviert..."
        Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -NoRestart | Out-Null
    }
    catch {
        Write-ErrorLog "Function MediaPlayerDeaktivieren: " + $_.Exception.Message
    }
}
MediaPlayerDeaktivieren

#IPv4 über IPv6 priorisieren
Function Set-IPv4Preferred {
    try {
        Write-Output "IPv4 wird gegenüber IPv6 bevorzugt..."

        #Registry-Zweig sicherstellen
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        if (-not (Test-Path -LiteralPath $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        Set-ItemProperty -Path $regPath -Name "DisabledComponents" -Type DWord -Value 0x20
        Write-Verbose "DisabledComponents=0x20 geschrieben."
    }
    catch {
        Write-ErrorLog "Function Set-IPv4Preferred: Fehler beim Setzen der IPv4/IPv6-Präferenz: " + $_.Exception.Message
    }
}
Set-IPv4Preferred

#---------------------------------------------------------------------------

#Löscht OneDrive
Function OneDrivelöschen {
    try {
        Write-Output "OneDrive wird deinstalliert..."
        Start-Process -FilePath winget -ArgumentList "uninstall -e --purge --accept-source-agreements Microsoft.OneDrive" -NoNewWindow -Wait
    }
    catch { Write-ErrorLog "Function OneDrivelöschen: " + $_.Exception.Message }
}
OneDrivelöschen

#Löschen von Temporären Windows Dateien / chocolatey Dateien
Function Tempslöschen {
    try {
        Write-Output "Temporäre Dateien werden gelöscht..."
        $folders = @("C:\Windows\Temp\*", "C:\Users\*\Appdata\Local\Temp\*", "C:\Windows\SoftwareDistribution\Download", "C:\Windows\System32\FNTCACHE.DAT", "C:\Users\*\Documents\WindowsPowerShell", "C:\ProgramData\chocolatey")
        foreach ($folder in $folders) {Remove-Item $folder -force -recurse -ErrorAction SilentlyContinue}
    }
    catch { Write-ErrorLog "Function Tempslöschen: " + $_.Exception.Message }
}
Tempslöschen

#--------------------------------------------------------------------------

# Windows Aktivierung mit Fehlerauswertung
Function windowsaktivieren {
    try {
        $output = & cscript.exe //nologo $env:windir\system32\slmgr.vbs -ato
        $output | Write-Output
        if ($output -match "Fehler:|Error:") {
            $hinweis = "Das Gerät besitzt keine Lizenz für die installierte Windows Version. Wähle das MDT-Image mit der übereinstimmenden Windows Version."
            throw ($output -join "`n") + $hinweis
        }
    }
    catch {
        Write-ErrorLog $_.Exception.Message
    }
}
windowsaktivieren

#--------------------------------------------------------------------------
Write-Output "Benötigte Software wird installiert..."
#Alle Geräte Standardprogramme //Aus Redundanzgründen drin lassen, OOBE verhaltet sich bei Installationen manchmal komisch
Function Installiere7Zip {
    try {
        winget install -e --id 7zip.7zip --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
    }
    catch {
        Write-ErrorLog "Function Installiere7Zip: " + $_.Exception.Message
    }
}
Installiere7Zip
Function InstalliereAdobeAcrobatReader {
    try {
        winget install -e --id Adobe.Acrobat.Reader.64-bit --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
    }
    catch {
        Write-ErrorLog "Function InstalliereAdobeAcrobatReader: " + $_.Exception.Message
    }
}
InstalliereAdobeAcrobatReader
Function InstalliereVLC {
    try {
        winget install -e --id VideoLAN.VLC --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
    }
    catch {
        Write-ErrorLog "InstalliereAdobeAcrobatReader: " + $_.Exception.Message
    }
}
InstalliereVLC
Function InstalliereFirefoxDE {
    try {
        winget install -e --id Mozilla.Firefox.de --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
    }
    catch {
        Write-ErrorLog "Function InstalliereFirefoxDE: " + $_.Exception.Message
    }
}
InstalliereFirefoxDE

#Lenovo (Vantage / Commercial Vantage)
Function InstalliereLenovoVantage {
    try {
        $systemManufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer.ToLower()
        $systemModel = (Get-WmiObject -Class Win32_ComputerSystem).Model.ToUpper()
		#Modellnummern müssen bei neuen Modellen entsprechend den Think- Modellnummern aktualisiert werden
        if ($systemManufacturer -like "*lenovo*") {
            if (
                $systemModel -like "10*" -or
                $systemModel -like "11*" -or
                $systemModel -like "12*" -or
                $systemModel -like "20*" -or
                $systemModel -like "21*" -or
                $systemModel -like "30*" -or
                $systemModel -like "31*" -or
                $systemModel -like "32*"
            ) {
                #Lenovo Commercial Vantage (Think-Serien)
                winget install -e --id 9NR5B8GVVM13 --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
            } else {
                #Lenovo Vantage (Consumer-Serien)
                winget install -e --id 9WZDNCRFJ4MV --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
            }
        }
    }
    catch {
        Write-ErrorLog "Function InstalliereLenovoVantage: " + $_.Exception.Message
    }
}
InstalliereLenovoVantage

#Acer (Care Center S)
Function InstalliereAcerCareCenter {
    try {
        $systemManufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
        if ($systemManufacturer -like "*Acer*") {
            winget install -e --id 9P8BB54NQNQ4 --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
        }
    }
    catch {
        Write-ErrorLog "Function InstalliereAcerCareCenter: " + $_.Exception.Message
    }
}
InstalliereAcerCareCenter

#HP (Support Assistant)
Function InstalliereHPSupportAssistant {
    try {
        $systemManufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
        if ($systemManufacturer -like "*HP*" -or $systemManufacturer -like "*Hewlett-Packard*") {
            choco install hpsupportassistant -y
        }
    }
    catch {
        Write-ErrorLog "Function InstalliereHPSupportAssistant: " + $_.Exception.Message
    }
}
InstalliereHPSupportAssistant

#Dell (Command Update)
Function InstalliereDellCommandUpdate {
    try {
        $systemManufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
        if ($systemManufacturer -like "*Dell*") {
            winget install -e --id Dell.CommandUpdate --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
        }
    }
    catch {
        Write-ErrorLog "Function InstalliereDellCommandUpdate: " + $_.Exception.Message
    }
}
InstalliereDellCommandUpdate

#Asus (MyAsus)
Function InstalliereAsusMyAsus {
    try {
        $systemManufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
        if ($systemManufacturer -like "*Asus*") {
            winget install -e --id 9N7R5S6B0ZZH --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
        }
    }
    catch {
        Write-ErrorLog "Function InstalliereAsusMyAsus: " + $_.Exception.Message
    }
}
InstalliereAsusMyAsus

#--------------------------------------------------------------------------

#Löschen von Windows Apps //Brauchts nicht mehr, falls provisioned packages gut funktioniert
Function MSAppslöschen {
    Write-Output "Windows Apps werden deinstalliert..."
  	Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
	Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
	Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
	Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
	Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
	Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
	Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage
	Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
	Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
	Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
	Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
	Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
	Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
	Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
	Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
	Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
	Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
	Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
	Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
	Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
	Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
	Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
	Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
	Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
	Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
	Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
	Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
	Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage
    Get-AppxPackage *solitairecollection* | Remove-AppxPackage
    Get-AppxPackage  Microsoft.549981C3F5F10 | Remove-AppxPackage 
    Get-AppxPackage *WebExperience* | Remove-AppxPackage #Entfernt Widgets von der Taskleiste
	Get-AppxPackage -Name "Microsoft.OutlookForWindows" | Remove-AppxPackage
	Get-AppxPackage -Name "MicrosoftTeams" | Remove-AppxPackage
	Get-AppxPackage -Name "Microsoft.Teams" | Remove-AppxPackage
    Get-AppxPackage -Name "MSTeams" | Remove-AppxPackage
	Get-AppxPackage -Name "Microsoft.Todos" | Remove-AppxPackage
    Get-AppxPackage -Name "Microsoft.LinkedIn" | Remove-AppxPackage
    Get-AppxPackage -AllUsers | Where-Object {$_.Name -like "*xbox*"} | Remove-AppxPackage
}
#MSAppslöschen

#Alle Verknüpfungen auf dem Desktop löschen
Function LöscheDesktop {
    try {
        Write-Output "Alle Verknüpfungen auf dem Desktop werden gelöscht..."
        Remove-Item "C:\Users\*\Desktop\*.lnk"
    }
    catch {
        Write-ErrorLog "Function LöscheDesktop: " + $_.Exception.Message
    }
}
LöscheDesktop

#Konfiguriert Teamviewer so, dass der Dienst nur startet, wenn der Benutzer den Link öffnet
function TeamViewer {
    param (
        $vbsPath = "C:\Program Files\TeamViewer\omikron_tv_start.vbs",
        $iconPath = "C:\Program Files\TeamViewer\TeamViewer.exe",
        $shortcutPath = "$env:PUBLIC\Desktop\Omikron Fernwartung.lnk",
        $backupShortcutPath = "C:\Program Files\TeamViewer\Omikron Fernwartung.lnk",
        $startMenuShortcutPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\TeamViewer.lnk",
        $dir = "C:\Program Files\TeamViewer"
    )
    try {
        #Teamviewer Dienst auf Manuell
        Set-Service -Name "TeamViewer" -StartupType Manual

        #Inhalt als Array
        $vbsContent = @(
            "' Autor: Tobias Hoesli / Omikron Data AG"
            "' Letzte Änderungen: 15.08.2025"
            "' !DO NOT DELETE! is used for a working desktop link: Starts both service and GUI"
            "' !NICHT LOESCHEN! wird für den funktionierenden Desktoplink verwendet: Startet sowohl Dienst als auch GUI"
            'Set WshShell = CreateObject("WScript.Shell")'
            "' Erst Dienst starten"
            'WshShell.Run """C:\Program Files\TeamViewer\TeamViewer.exe"" --ControlServiceStart", 0, True'
            "' 2 Sekunden warten, damit der Dienst hochkommt"
            'WScript.Sleep 2000'
            "' Dann GUI starten"
            'WshShell.Run """C:\Program Files\TeamViewer\TeamViewer.exe""", 0, False'
        )
        #Datei schreiben
        Set-Content -Path $vbsPath -Value $vbsContent -Encoding ASCII

        #Shortcut auf Desktop
        $wshell = New-Object -ComObject WScript.Shell
        $shortcut = $wshell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "wscript.exe"
        $shortcut.Arguments = "`"$vbsPath`""
        $shortcut.IconLocation = $iconPath
        $shortcut.WorkingDirectory = $dir
        $smShortcut.Description = "TeamViewer"
        $shortcut.Save()

        #Shortcut im TeamViewer-Ordner (Backup)
        $backupShortcut = $wshell.CreateShortcut($backupShortcutPath)
        $backupShortcut.TargetPath = "wscript.exe"
        $backupShortcut.Arguments = "`"$vbsPath`""
        $backupShortcut.IconLocation = $iconPath
        $backupShortcut.WorkingDirectory = $dir
        $smShortcut.Description = "TeamViewer"
        $backupShortcut.Save()

        #Shortcut für den Start (Suche und Programmliste) anpassen
        $smShortcut = $wshell.CreateShortcut($startMenuShortcutPath)
        $smShortcut.TargetPath = "wscript.exe"
        $smShortcut.Arguments = "`"$vbsPath`""
        $smShortcut.IconLocation = $iconPath
        $smShortcut.WorkingDirectory = $dir
        $smShortcut.Description = "Omikron Fernwartung"
        $smShortcut.Save()
    }
    catch {
        Write-ErrorLog "function TeamViewer: " + $_.Exception.Message
    }
}
TeamViewer

#VLC Konfiguration
function VLCconfig {
    # Pfad ins Roaming-AppData des aktuellen Users
    $vlcPath = Join-Path $env:APPDATA 'vlc'
    $vlcrc   = Join-Path $vlcPath 'vlcrc'
    try {
        Write-Host "VLC wird konfiguriert..."
        #Ordner anlegen, falls nicht vorhanden
        if (-not (Test-Path -LiteralPath $vlcPath)) {
            New-Item -ItemType Directory -Path $vlcPath -Force | Out-Null
            Write-Verbose "Ordner erstellt: $vlcPath"
        }
        #Config als Array
        $configLines = @(
            'qt-privacy-ask=0'
            'qt-privacy-asklater=0'
        )
        #Datei schreiben
        Set-Content -Path $vlcrc -Value $configLines -Encoding ASCII -Force
        Write-Verbose "Konfiguration geschrieben nach: $vlcrc"
    }
    catch {
        Write-ErrorLog "Function VLCconfig: " + $_.Exception.Message
    }
}
VLCconfig

#AcrobatReader Willkommenscreen deaktivieren
function Adobeconfig {
    param (
        $regPath = "HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown"
    )
    try {
        Write-Host "Adobe Acrobat Reader wird konfiguriert..."
        #Falls der Pfad nicht existiert, erstellen
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        New-ItemProperty -Path $regPath -Name "bToggleFTE"   -Value 1 -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $regPath -Name "bWhatsNewExp" -Value 1 -PropertyType DWORD -Force | Out-Null
    }
    catch {
        Write-ErrorLog "function Adobeconfig: " + $_.Exception.Message
    }
}
Adobeconfig

#Taskleiste bereinigen
Function TaskleisteLeeren {
    try {
        Write-Output "Taskleiste wird bereinigt..."
        # Explorer beenden
        Stop-Process -Name explorer -Force
        # Taskleisten-Verknüpfungen löschen
        Remove-Item "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*" -Force -ErrorAction SilentlyContinue
        # Registry-Taskband-Branch löschen und neu anlegen
        Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Recurse -ErrorAction SilentlyContinue
        New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" | Out-Null
        Start-Process explorer.exe
    }
    catch {
        Write-ErrorLog "Function TaskleisteLeeren: " + $_.Exception.Message
    }
}
TaskleisteLeeren

#UAC aktivieren
Function UACAktivieren {
    try {
        Write-Output "UAC (Benutzerkontensteuerung) wird wieder aktiviert..."
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1
    }
    catch {
        Write-ErrorLog "Function UACAktivieren: " + $_.Exception.Message
    }
}
UACAktivieren

#Wiederherstellungspunkt
Function WiederherstellungspunktErstellen {
    try {
        #24h-Restorepoint Limite deaktiviert
        Write-Verbose "24h-Limit für Wiederherstellungspunkt wird deaktiviert..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0 -Type DWord

        #Preloadfix Wiederherstellungspunkt erstellen
        Write-Output "Wiederherstellungspunkt wird erstellt..."

        #24h-Restorepoint Limite wieder aktiviert
        Write-Verbose "24h-Limit wird wieder aktiviert..."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -ErrorAction Stop
    }
    catch {
        Write-ErrorLog "Function WiederherstellungspunktErstellen: " + $_.Exception.Message
    }
}
WiederherstellungspunktErstellen

#Aktiviere um Funktion des try/catch logs zu testen
Function Test-ForcedError {
    try {
        #Das funktioniert garantiert nicht
        Remove-Item "C:\DateiDieNichtExistiert.txt"
    }
    catch {
        Write-ErrorLog "Function Test-ForcedError: " + $_.Exception.Message
    }
}
#Test-ForcedError

#--------------------------------------------------------------------------

#Abschliessende Commands
try {
    Remove-Item -Path $MyInvocation.MyCommand.Source -Force
} catch { Write-ErrorLog $_.Exception.Message }
try {
    Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\RunPS1.bat" -Force
} catch { Write-ErrorLog $_.Exception.Message }
try {
    stop-transcript
} catch { Write-ErrorLog $_.Exception.Message }
try {
    Restart-Computer
} catch { Write-ErrorLog $_.Exception.Message }