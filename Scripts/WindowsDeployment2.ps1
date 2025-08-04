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


clear
#--------------------------------------------------------------------------


start-transcript C:\Windows\WindowsDeployment2.log

#Wird nicht mehr benutzt! => Alles in WD_Universal integriert