
#--------------------------------------------------------------------------

$ConfirmPreference = "None"
$ErrorActionPreference = "Continue"

#--------------------------------------------------------------------------

start-transcript C:\Windows\applications.log

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

function Install-IfManufacturerAndModel {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredManufacturers,
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredModels,
        [Parameter(Mandatory = $true)]
        [string]$InstallCommand
    )
    $systemManufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    $systemModel = (Get-WmiObject -Class Win32_ComputerSystem).Model
    foreach ($manu in $RequiredManufacturers) {
        foreach ($model in $RequiredModels) {
            if (($systemManufacturer -like "*$manu*") -and ($systemModel -like "*$model*")) {
            if (($systemManufacturer -like "*$manu*") -and ($systemModel -like "*$model*")) {
                Invoke-Expression $InstallCommand
                break
            }
            }
        }
    }
}

$env:PATH += ";C:\ProgramData\chocolatey\bin"
#--------------------------------------------------------------------------

#WICHTIG!!: Jegliche Software, die als MSStore-App installiert wird, muss im Skript WindowsDeployment2.ps1 hinterlegt werden, da MSStore-Apps nur für den aktiven Benutzer installiert werden (in diesem Schritt ist das noch Administrator). 
#Am besten hinterlegt ihr die MSStore-Apps sowohl hier als auch in WindowsDeployment2.ps1
#Ob es sich bei einer installation um ein Programm oder eine App handelt sehr ihr, wenn ihr in cmd nach dem Program sucht: winget search "Name oder ID"
#Wenn als Quelle winget steht, ist es ein Programm. Wenn msstore steht, eine MSStore-App.
#Chocolatey installationen sind immer Programme

#Edit: Kopiert einfach den ganzen Block ins WindowsDeployment2.ps1. Bereits vorhandene Software wird übersprungen, nicht vorhandene installiert.

#Alle Geräte Standardprogramme //Da Winget im OOBE nicht funktioniert zwingend mit chocolatey installieren!
choco install adobereader -y
choco install firefox -y
choco install vlc -y
choco install teamviewer.host -y
choco install 7zip -y


#Lenovo Thinkpad (Commercial Vantage)
Install-IfManufacturerAndModel `
  -RequiredManufacturers @("Lenovo") `
  -RequiredModels @("ThinkPad") `
  -InstallCommand 'winget install -e --id 9NR5B8GVVM13 --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

#Lenovo Ideapad (Vantage)
Install-IfManufacturerAndModel `
  -RequiredManufacturers @("Lenovo") `
  -RequiredModels @("IdeaPad") `
  -InstallCommand 'winget install -e --id 9WZDNCRFJ4MV --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

#Acer (Care Center S)
Install-IfManufacturerMulti -RequiredManufacturers @("Acer") -InstallCommand 'winget install -e --id 9P8BB54NQNQ4 --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

#HP (Support Assistant)
Install-IfManufacturerMulti -RequiredManufacturers @("HP","Hewlett-Packard") -InstallCommand 'choco install hpsupportassistant -y'

#Dell (Command Update)
Install-IfManufacturerMulti -RequiredManufacturers @("Dell") -InstallCommand 'winget install -e --id Dell.CommandUpdate --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

#Asus (MyAsus)
Install-IfManufacturerMulti -RequiredManufacturers @("Asus") -InstallCommand 'winget install -e --id 9N7R5S6B0ZZH --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

#Microsoft Surface (Surface)
Install-IfManufacturerAndModel `
  -RequiredManufacturers @("Microsoft") `
  -RequiredModels @("Surface") `
  -InstallCommand 'winget install -e --id 9WZDNCRFJB8P --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

stop-transcript