
#Funktioniert nur mit Pro Geräten: manipuliert Windows, damit gewisse Einstellungen nicht blockiert werden
function FakeEnrollmentConfig {
    param (
        [ValidateSet("Add", "Remove")]
        [string]$Action = "Add"
    )
    $EnrollmentsPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
    $OMADMPath       = "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
    if ($Action -eq "Add") {
        Write-Host "Füge Fake Enrollment Registry Keys hinzu..."
        # Enrollments Keys
        if (-not (Test-Path $EnrollmentsPath)) { New-Item -Path $EnrollmentsPath -Force | Out-Null }
        New-ItemProperty -Path $EnrollmentsPath -Name "EnrollmentState" -PropertyType DWord -Value 1 -Force
        New-ItemProperty -Path $EnrollmentsPath -Name "EnrollmentType" -PropertyType DWord -Value 0 -Force
        New-ItemProperty -Path $EnrollmentsPath -Name "IsFederated" -PropertyType DWord -Value 0 -Force
        # OMADM Accounts Keys
        if (-not (Test-Path $OMADMPath)) { New-Item -Path $OMADMPath -Force | Out-Null }
        New-ItemProperty -Path $OMADMPath -Name "Flags" -PropertyType DWord -Value 14089087 -Force
        New-ItemProperty -Path $OMADMPath -Name "AcctUId" -PropertyType String -Value "0x000000000000000000000000000000000000000000000000000000000000000000000000" -Force
        New-ItemProperty -Path $OMADMPath -Name "RoamingCount" -PropertyType DWord -Value 0 -Force
        New-ItemProperty -Path $OMADMPath -Name "SslClientCertReference" -PropertyType String -Value "MY;User;0000000000000000000000000000000000000000" -Force
        New-ItemProperty -Path $OMADMPath -Name "ProtoVer" -PropertyType String -Value "1.2" -Force
        Write-Host "Fake Enrollment Keys wurden hinzugefügt."
    }
    elseif ($Action -eq "Remove") {
        Write-Host "Entferne Fake Enrollment Registry Keys..."
        if (Test-Path $EnrollmentsPath) { Remove-Item -Path $EnrollmentsPath -Recurse -Force }
        if (Test-Path $OMADMPath) { Remove-Item -Path $OMADMPath -Recurse -Force }
        Write-Host "Fake Enrollment Keys wurden entfernt."
    }
}
# Beispiele:
#FakeEnrollmentConfig -Action Add
#FakeEnrollmentConfig -Action Remove