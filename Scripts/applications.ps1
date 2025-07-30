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
winget install --id 7zip.7zip --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install --id TeamViewer.TeamViewer.Host --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install --id Adobe.Acrobat.Reader.64-bit --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install --id VideoLAN.VLC --disable-interactivity --silent --accept-package-agreements --accept-source-agreements
winget install --id Mozilla.Firefox.de --disable-interactivity --silent --accept-package-agreements --accept-source-agreements

#Lenovo Thinkpad
Install-IfManufacturerAndModel `
  -RequiredManufacturers @("Lenovo") `
  -RequiredModels @("ThinkPad") `
  -InstallCommand 'winget install "Lenovo Commercial Vantage" --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

#Lenovo Ideapad
Install-IfManufacturerAndModel `
  -RequiredManufacturers @("Lenovo") `
  -RequiredModels @("IdeaPad") `
  -InstallCommand 'winget install "Lenovo Vantage" --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

#Acer
Install-IfManufacturerMulti -RequiredManufacturers @("Acer") -InstallCommand 'winget install "Care Center S" --disable-interactivity --silent --accept-package-agreements --accept-source-agreements'

#HP
Install-IfManufacturerMulti -RequiredManufacturers @("HP","Hewlett-Packard") -InstallCommand 'choco install hpsupportassistant -y'

#Deinstallation Chocolatey
if (Test-Path "$env:ProgramData\chocolatey") {
	Remove-Item -Recurse -Force "$env:ProgramData\chocolatey"
}