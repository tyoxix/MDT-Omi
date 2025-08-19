
#Kleinste SSD (inkl. NVMe/M.2) > 60 GB ermitteln und Disknummer ausgeben
$minGB = 60

#Versuch 1: Storage-API (sauber: MediaType/BusType)
$pd = Get-CimInstance -Namespace root\microsoft\windows\storage -Class MSFT_PhysicalDisk -ErrorAction SilentlyContinue |
      Where-Object { ( $_.MediaType -eq 'SSD' -or $_.BusType -eq 'NVMe' ) -and ($_.Size/1GB) -gt $minGB } |
      Sort-Object Size | Select-Object -First 1

if ($pd) {
    $disk = Get-Disk | Where-Object { $_.FriendlyName -eq $pd.FriendlyName } |
            Sort-Object Size | Select-Object -First 1
} else {
#Versuch 2 (Fallback): Heuristik über Modell/FriendlyName
    $disk = Get-Disk | Where-Object {
        ( $_.BusType -eq 'NVMe' -or $_.FriendlyName -match '(?i)(SSD|NVMe|M\.2|Solid\s*State)' ) -and
        ($_.Size/1GB) -gt $minGB
    } | Sort-Object Size | Select-Object -First 1
}

#Ausgabe: Disknummer + Info
if ($disk) {
    [pscustomobject]@{
        DiskNumber   = $disk.Number
        SizeGB       = [math]::Round($disk.Size/1GB,2)
        BusType      = $disk.BusType
        FriendlyName = $disk.FriendlyName
    }
} else {
    Write-Warning "Keine passende SSD/NVMe > $minGB GB gefunden."
}