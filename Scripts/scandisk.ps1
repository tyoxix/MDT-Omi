	# Get list of all not USB disks
	$disks = Get-Disk | Where-Object -FilterScript {$_.BusType -ne "USB"}

	# Clear all disks from list
	$disks | Clear-Disk -RemoveData -RemoveOEM

	#Find the smallest disk (without USB)
	$OSDiskNumber = Get-Disk | Where-Object -FilterScript {$_.BusType -ne "USB"} | Sort-Object -Property "Total Size" -Ascending| Select-Object -First 1 | Select-Object -ExpandProperty Number

	#Load MDT Environment Variables
	$TSEnv = New-Object -ComObject Microsoft.SMS.TSEnvironment

	#Modify OSDDiskIndex Value
	$TSEnv.value("OSDDiskIndex") = $OSDiskNumber
