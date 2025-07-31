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

#--------------------------------------------------------------------------

#Alle Geräte Standardprogramme
winget install -e --id 7zip.7zip --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install -e --id TeamViewer.TeamViewer.Host --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install -e --id Adobe.Acrobat.Reader.64-bit --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install -e --id VideoLAN.VLC --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install -e --id Mozilla.Firefox.de --disable-interactivity --silent --accept-package-agreements --accept-source-agreements

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