<#
Autor: Tobias Hösli / Omikron Data AG
Erstellt: 25.08.2025
Zeigt nach dem USMT-Capture den Speicherort an und blockiert, bis Enter gedrückt wird
#>

try {
    $ts = New-Object -ComObject Microsoft.SMS.TSEnvironment
    $udShare = $ts.Value('UDShare')
    $udDir   = $ts.Value('UDDir')
    $osd     = $ts.Value('OSDStateStorePath')

    # Pfad ermitteln: OSDStateStorePath > UDShare\UDDir > UDShare
    if ([string]::IsNullOrWhiteSpace($osd)) {
        if (-not [string]::IsNullOrWhiteSpace($udShare)) {
            $path = $udShare + ($(if ($udDir) { '\' + $udDir } else { '' }))
        } else { $path = '<unbekannt>' }
    } else { $path = $osd }

    # Anzeige
    Write-Host ''
    Write-Host '==============================================='
    Write-Host '   USMT-Übernahme abgeschlossen'
    Write-Host "   Speicherort: $path"
    Write-Host '==============================================='
    Write-Host ''
    Write-Host 'Beim Restore diesen Pfad auf dem neuen Gerät angeben'
    Write-Host ''

    # Blockieren bis Enter
    Read-Host 'Neustart mit [Enter]'
}
catch {
    Write-Host 'Fehler beim Anzeigen des USMT-Pfads:' $_.Exception.Message
    Read-Host 'Neustart mit [Enter]'
}