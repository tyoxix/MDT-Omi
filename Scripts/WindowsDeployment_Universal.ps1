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

Write-Output ""
#Read-Host "Drücke Enter um das Gerät neu zu starten"

Remove-Item -Path $MyInvocation.MyCommand.Source -Force
Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\RunPS1.bat" -Force
Move-Item "C:\Windows\RunPS2.bat" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\RunPS2.bat"

stop-transcript
Restart-Computer