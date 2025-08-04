<#
Autor: Tobias Hösli / Omikron Data AG
Letzte Änderungen: 31.07.2025

Neue, automatisiertere Version von WindowsDeployment.ps1.
Dieses Script führt folgende Aufgaben aus:

Konfigurationen:
    Windows Festplatte in "System" umbenennen
    Anzeigen von "Dieser PC" auf Desktop
    Anzeigen des Benutzerordners auf Dektop
    Kleine Symbole in Systemsteuerung festlegen
    Defragmentierung Ausschalten
    ScmartScreen deaktivieren
    Windows Light-Mode deaktivieren
    Zuletzt hinzugefügte Apps ausschalten
    Explorer öffnen für "Dieser PC"
    Tastaturlayout Französisch (Schweiz) & Deutsch (Deutschland) löschen
    Löschen von "Fax" und "Microsoft XPS Document Writer" Druckern
    Uhrzeit Synchronisieren
    Action Center deaktivieren (App Icons) / Benachrichtigungen anzeigen
    Explorer Datenschutzoptionen
    NumLock immer aktiviert
	Windows 11 Rechtsklick deaktivieren
    Taskleiste bereinigen
    Sekundäre Festplatte als "Daten" formatieren
    OneDrive löschen
    Alle Verknüpfungen auf dem Desktop löschen
    Löschen von Temporären Windows Dateien / chocolatey Dateien
    Windows Aktivieren

	Fix with other Script
		    Appvorschläge Ausschalten
			Darkmode?
			

Rausputzen:
    Alle Verknüpfungen auf dem Desktop Löschen
    Temporäre Dateien
    Deinstallation OneDrive

Diverses:
    Windows Aktivierung
    Wiederherstellungspunkt
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

#--------------------------------------------------------------------------

$ConfirmPreference = "None"
$ErrorActionPreference = "Continue"

#--------------------------------------------------------------------------
clear

start-transcript C:\Windows\WindowsDeployment.log
Stop-Process -ProcessName explorer -Force

#Windows Festplatte zu "System" umbenennen
Function Festplatteumbenennen {
    Write-Output "Windows Festplatte wird umbenannt..."
    Set-Volume -DriveLetter C -NewFileSystemLabel "System"
}
Festplatteumbenennen

#Anzeigen von "Dieser PC" auf Desktop
Function DieserPCaufDesktop {
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
DieserPCaufDesktop

#Anzeigen des Benutzerordners auf Dektop
Function BenutzerordneraufDesktop {
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
BenutzerordneraufDesktop

#Kleine Symbole in Systemsteuerung festlegen
Function SystemsteuerungKleineSymbole {
	Write-Output "Kleine Symbole werden in Systemsteuerung festgelegt..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1
}
SystemsteuerungKleineSymbole

#ScmartScreen deaktivieren
Function Smartscreendeaktivieren {
	Write-Output "SmartScreen wird deaktiviert..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
}
Smartscreendeaktivieren

#Windows Darkmode aktivieren
Function DarkModeAktivieren {
    Write-Output "Windows Dark Mode wird aktiviert..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" | Out-Null
    }
    # Dark Mode für Apps
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
    # Dark Mode für System/Oberfläche (Taskleiste, Startmenü)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
}
DarkModeAktivieren

#Explorer für "Dieser PC" Öffnen
Function ExplorerfürDieserPC {
	Write-Output "Setze Explorer öffnen für Dieser PC..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 -Force | Out-Null
}
ExplorerfürDieserPC

#Französisch (Schweiz) & Deutsch (Deutschland) löschen
Function löschetastaturen {
    Write-Output "Französisch (Schweiz) Tastaturlayout wird entfernt..."
    $langs = Get-WinUserLanguageList
    Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "fr-CH"}) -Force
    Write-Output "Deutsch (Deutschland) Tastaturlayout wird entfernt..."
    $langs = Get-WinUserLanguageList
    Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "de-DE"}) -Force
    }
löschetastaturen

#Löschen von "Fax" und "Microsoft XPS Document Writer" Druckern 
Function LöscheDrucker {
	Write-Output "Fax Drucker wird entfernt..."
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue | Out-Null
    Write-Output "Microsoft XPS Document Writer Drucker wird entfernt..."
    Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
LöscheDrucker

#Synchronisierung der Uhrzeit
Function Uhrzeit {
    Write-Output "Uhrzeit wird synchronisiert..."
    net stop w32time >$null 2>&1
    net start w32time >$null 2>&1
    W32tm /config /manualpeerlist:time.windows.com,0x8 /syncfromflags:MANUAL >$null 2>&1
    W32tm /config /update >$null 2>&1
}
Uhrzeit

#Action Center deaktivieren (App Icons) / Benachrichtigungen anzeigen
Write-Output "Action Center wird konfiguriert... "
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_GLEAM_ENABLED" -Type DWord -Value 0 -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_BADGE_ENABLED" -Type DWord -Value 0 -Force | Out-Null

#Explorer Datenschutzoptionen
Write-output "Explorer Datenschutzeinstellungen werden konfiguriert..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0 -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 -Force | Out-Null

#Dateiendungen anzeigen
Write-output "Dateiendungen werden aktiviert..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord -Force | Out-Null

#Suchleiste als Lupe anzeigen
Write-output "Suchleiste als Lupe anzeigen wird aktiviert..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1 -Force | Out-Null

#NumLock dauerhaft aktivieren
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

#Altes Kontextmenü / Recktsklick aktivieren
Write-Output "Altes Windows Menü wird aktiviert..."
New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -Value "" -Force | Out-Null

#Chat von Taskbar lösen
Write-Output "Chat wird von der Taskleiste entfernt..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type DWord -Value 0 | Out-Null

#Bing-Websuche deaktivieren
Function WebsucheDeaktivieren { 
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
WebsucheDeaktivieren

#Detailed BlueScreen aktivieren
Function DetailedBsodAktivieren {
    Write-Output "Detailed (klassischer) Bluescreen wird aktiviert..."
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
    If (!(Test-Path $regPath)) {
        New-Item -Path $regPath | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "DisplayParameters" -Type DWord -Value 1
}
DetailedBsodAktivieren

#Starteinstellungen anpassen
Function Startmenu {
   Type DWord -Value 1
	#Meistverwendete Apps anzeigen
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackFrequent" -Type DWord -Value 1
	#Empfehlungen für Tipps, Verknüpfungen, neue Apps deaktivieren
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Type DWord -Value 0
	#Kontobezogene Benachrichtigungen deaktivieren
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_AccountNotifications" -Type DWord -Value 0
}
Startmenu

#Energieeinstellungen anpassen
Function Energiesparplan {
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
Energiesparplan

#Find the smallest disk (without USB)
$OSDiskNumber = Get-Disk | Where-Object -FilterScript {$_.BusType -ne "USB"} | Sort-Object -Property "Total Size" -Descending | Select-Object -Last 1 | Select-Object -ExpandProperty Number
#Find the largest disk (without USB)
$seconddisk = Get-Disk | Where-Object -FilterScript {$_.BusType -ne "USB"} | Sort-Object -Property "Total Size" -Descending | Select-Object -First 1 | Select-Object -ExpandProperty Number
#Format second largest disk as "Daten" (if not the same as smallest disk)
if($OSDiskNumber -ne $seconddisk){
	Initialize-Disk -Number $seconddisk | Out-Null
	new-partition -disknumber $seconddisk -usemaximumsize | format-volume -filesystem NTFS -newfilesystemlabel Daten | Out-Null
	Get-WmiObject -Class Win32_volume -Filter 'DriveType=5' | Select-Object -First 1 | Set-WmiInstance -Arguments @{DriveLetter='E:'} | Out-Null
	Get-CimInstance -classname Win32_volume | ?{$_.Label -eq 'Daten'} | Set-CimInstance -Arguments @{Driveletter="D:"} | Out-Null
	Write-Output "Sekundäre Festplatte wurde als 'Daten' formatiert"
}

#Edge Debloat
Function EdgeDebloat{
    Write-Host "Edge wird deabloated..."
    #EdgeUpdate
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "CreateDesktopShortcutDefault" -Type DWord -Value 0
    #Edge Policies
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
EdgeDebloat 

#Windows Media Player deaktivieren
Write-Host "Windows Media Player wird deaktiviert..."
Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -NoRestart

#---------------------------------------------------------------------------

#Löscht OneDrive
Function OneDrivelöschen {
Write-Output "OneDrive wird deinstalliert..."
Start-Process -FilePath winget -ArgumentList "uninstall -e --purge --accept-source-agreements Microsoft.OneDrive" -NoNewWindow -Wait
}
OneDrivelöschen

#Löschen von Temporären Windows Dateien / chocolatey Dateien
Function Tempslöschen {
    Write-Output "Temporäre Dateien werden gelöscht..."
    $folders = @("C:\Windows\Temp\*", "C:\Users\*\Appdata\Local\Temp\*", "C:\Windows\SoftwareDistribution\Download", "C:\Windows\System32\FNTCACHE.DAT", "C:\Users\*\Documents\WindowsPowerShell", "C:\ProgramData\chocolatey")
    foreach ($folder in $folders) {Remove-Item $folder -force -recurse -ErrorAction SilentlyContinue}
}
Tempslöschen

#--------------------------------------------------------------------------

#Windows Aktivierung
Start-Process -FilePath "cscript.exe" -ArgumentList "//nologo $env:windir\system32\slmgr.vbs -ato" -NoNewWindow -Wait

#--------------------------------------------------------------------------
Write-Output "Benötigte Software wird installiert..."

#Alle Geräte Standardprogramme //Aus Redundanzgründen drin lassen, OOBE verhaltet sich bei Installationen manchmal komisch
winget install -e --id 7zip.7zip --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install -e --id TeamViewer.TeamViewer.Host --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install -e --id Adobe.Acrobat.Reader.64-bit --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install -e --id VideoLAN.VLC --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install -e --id Mozilla.Firefox.de --disable-interactivity --silent --accept-package-agreements --accept-source-agreements

#Bei Microsoftgeräten wird die entsprechende Software automatisch per Windowsupdates installiert
$systemManufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer.ToLower()
$systemModel = (Get-WmiObject -Class Win32_ComputerSystem).Model.ToUpper()

#Lenovo (Vantage / Commercial Vantage)
if ($systemManufacturer -like "*lenovo*") {
    if ($systemModel -like "20*" -or $systemModel -like "21*") { #List erweitern, sollte Lenovo eine neue Modellogik nutzen
        #Lenovo Commercial Vantage (Think-)
        winget install -e --id 9NR5B8GVVM13 --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
    } else {
        #Lenovo Vantage (Idea-)
        winget install -e --id 9WZDNCRFJ4MV --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
    }
}

function Install-IfManufacturerMulti {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$RequiredManufacturers,
        [Parameter(Mandatory=$true)]
        [string]$InstallCommand
    )
    $systemManufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    foreach ($req in $RequiredManufacturers) {
        if ($systemManufacturer -like "*$req*") {
            Invoke-Expression $InstallCommand
            break
        }
    }
}

#Acer (Care Center S)
Install-IfManufacturerMulti -RequiredManufacturers @("Acer") -InstallCommand 'winget install -e --id 9P8BB54NQNQ4 --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

#HP (Support Assistant)
Install-IfManufacturerMulti -RequiredManufacturers @("HP","Hewlett-Packard") -InstallCommand 'choco install hpsupportassistant -y'

#Dell (Command Update)
Install-IfManufacturerMulti -RequiredManufacturers @("Dell") -InstallCommand 'winget install -e --id Dell.CommandUpdate --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

#Asus (MyAsus)
Install-IfManufacturerMulti -RequiredManufacturers @("Asus") -InstallCommand 'winget install -e --id 9N7R5S6B0ZZH --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

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
MSAppslöschen

#Alle Verknüpfungen auf dem Desktop löschen
Function LöscheDesktop {
    Write-Output "Alle Verknüpfungen auf dem Desktop werden gelöscht..."
    Remove-Item "C:\Users\*\Desktop\*.lnk" }
LöscheDesktop

#Teamviewer auf Desktop
Write-Output "Omikron Fernwartung wird auf Desktop verlinkt..."
$Path = "C:\Program Files\TeamViewer\TeamViewer.exe"
$linkPath = "$env:PUBLIC\Desktop\Omikron Fernwartung.lnk"
$wshell = New-Object -ComObject WScript.Shell
$shortcut = $wshell.CreateShortcut($linkPath)
$shortcut.TargetPath = $Path
$shortcut.WorkingDirectory = Split-Path $Path
$shortcut.IconLocation = $Path
$shortcut.Save()

#UAC aktivieren
Write-Output "UAC (Benutzerkontensteuerung) wird wieder aktiviert..."
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1

#Wiederherstellungpunkt erstellen
Write-Output "Wiederherstellungspunkt wird erstellt..."
Checkpoint-Computer -Description „Omikron Data AG Scriptfix“ -RestorePointType „MODIFY_SETTINGS“

Write-Output ""

#--------------------------------------------------------------------------

Remove-Item -Path $MyInvocation.MyCommand.Source -Force
Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\RunPS1.bat" -Force
stop-transcript
Restart-Computer