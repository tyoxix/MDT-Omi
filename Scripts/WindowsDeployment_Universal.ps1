<#
Autor: Tobias Hösli
Letzte Änderungen: 30.07.2025

Neue, automatisiertere Version von WindowsDeployment.ps1.
Dieses Script führt folgende Aufgaben aus:

Konfigurationen:
    -Windows Festplatte in "System" umbenennen
    -Anzeigen von "Dieser PC" auf Desktop
    -Anzeigen des Benutzerordners auf Dektop
    -Taskansicht-Schaltfläche Ausschalten
    -Kontakte auf der Taskleiste Ausschalten
    -Suchsymbol auf der Taskleiste aktivieren
    -Benutzerkontensteuerung Ausschalten
    -Kleine Symbole in Systemsteuerung festlegen
    -Defragmentierung Ausschalten
    -Appvorschläge Ausschalten
    -ScmartScreen deaktivieren
    -Windows Light-Mode deaktivieren
    -Zuletzt hinzugefügte Apps ausschalten
    -Explorer öffnen für "Dieser PC"
    -Alle Icons werden von der Taskleiste gelöst
    -Tastaturlayout Französisch (Schweiz) & Deutsch (Deutschland) löschen
    -Gelegentliche Appvorschläge ausschalten                    
    -Löschen von "Fax" und "Microsoft XPS Document Writer" Druckern 
    -Uhrzeit Synchronisieren
    -Explorer Datenschutzeinstellungen konfigurieren
    -Windows Action Center konfigurieren
    -Explorer Menuleiste herunterklappen

Rausputzen:
    -Windows Apps
    -Alle Verknüpfungen auf dem Desktop Löschen
    -Temporäre Dateien
    -Deinstallation oneDrive

Diverses:
    -Windows Aktivierung
    -Wiederherstellungspunkt
    -ToDo Liste
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

$ConfirmPreference = “None”
$ErrorActionPreference = "SilentlyContinue"

#--------------------------------------------------------------------------
clear

start-transcript C:\Windows\Deploy.log

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

#Defragmentierung Ausschalten
Function DefragmentierungAusschalten {
	Write-Output "Defragmentierung wird ausgeschalten..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}
DefragmentierungAusschalten

 #Appvorschläge Ausschalten
Function Appvorschlägeausschalten {
	Write-Output "Gelegentliche Appvorschläge werden ausgeschalten..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 | Out-Null
}
Appvorschlägeausschalten

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

#Windows Light-Mode deaktivieren
Function lightmodedeaktivieren {
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -Value 0 -Type Dword -Force
}
lightmodedeaktivieren

#Explorer für "Dieser PC" Öffnen
Function ExplorerfürDieserPC {
	Write-Output "Setze Explorer öffnen für Dieser PC..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
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
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
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
Write-output "Explorer Datenschutzeinstellungen werden konfiguriert...."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")) {
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0 -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 -Force | Out-Null

#Unpin Microsoft Edge from Taskbar
Write-Output "Microsoft Edge wird von der Taskleiste entfernt..."
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\Favorites" -Recurse -Force

#Unpin Chat from Taskbar
Write-Output "Chat wird von der Taskleiste entfernt..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type DWord -Value 0 | Out-Null

#Unpin Widgets from Taskbar
Write-Output "Widgets wird von der Taskleiste entfernt..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0 | Out-Null

#Enabling NumLock after startup
Write-Host "Aktiviere NumLock dauerhaft..."
   If (!(Test-Path "HKU:")) {
      New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
   }
   Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
   Add-Type -AssemblyName System.Windows.Forms
   If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
       $wsh = New-Object -ComObject WScript.Shell
       $wsh.SendKeys('{NUMLOCK}')
   }
   
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
taskkill /f /im OneDrive.exe | Out-Null
C:\Windows\SysWOW64\OneDriveSetup.exe /uninstall
}
OneDrivelöschen

#Alle Verknüpfungen auf dem Desktop löschen
Function LöscheDesktop {
    Write-Output "Alle Verknüpfungen auf dem Desktop werden gelöscht..."
    Remove-Item "C:\Users\*\Desktop\*.lnk" }
LöscheDesktop

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

Write-Output ""
Read-Host "Drücke Enter um das Gerät neu zu starten"

Remove-Item -Path $MyInvocation.MyCommand.Source -Force
Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\RunPS1.bat" -Force
Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Vantage.bat" -Force
Move-Item "C:\Windows\RunPS2.bat" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\RunPS2.bat"

stop-transcript
Restart-Computer