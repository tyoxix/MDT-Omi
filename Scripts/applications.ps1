$ConfirmPreference = "None"
$ErrorActionPreference = "Continue"

$env:PATH += ";C:\ProgramData\chocolatey\bin" #Muss bei OOBE definiert werden

start-transcript C:\Windows\applications.log

#--------------------------------------------------------------------------

#WICHTIG!!: Jegliche Software, die als MSStore-App installiert wird, muss im Skript WindowsDeployment2.ps1 hinterlegt werden, da MSStore-Apps nur für den aktiven Benutzer installiert werden (in diesem Schritt ist das noch Administrator). 
#Ob es sich bei einer installation um ein Programm oder eine App handelt sehr ihr, wenn ihr in cmd nach dem Program sucht: winget search "Name oder ID"
#=> Wenn als Quelle winget steht, ist es ein Programm. Wenn msstore steht, eine MSStore-App.
#=> Chocolatey installationen sind immer Programme

#Deshalb hier Standardprogramme mit Chocolatey installieren und Herstellerabhängige Software in WindowsDeployment2.ps1

#Alle Geräte Standardprogramme //Da Winget im OOBE nicht funktioniert zwingend mit chocolatey installieren!
choco install adobereader -y
choco install firefox -y
choco install vlc -y
choco install teamviewer.host -y
choco install 7zip -y

#--------------------------------------------------------------------------

stop-transcript