$OldLocation='c:\Website'
$NewLocation='c:\Temp'
$Files=250
$Runs=3
$Type='*.html'
##Lines to modify are above, will create new location folder
$RenameLocation = $OldLocation
$RCount=0
$LogFileLocation=(split-path $NewLocation -parent)
$LogFile="$LogFileLocation\WordListLog.log"
New-Item -Path (split-path $NewLocation) -Name (split-path $NewLocation -leaf) -ItemType "directory"
Start-Transcript -Path $LogFile
write-output "Renaming $Type to Split*.txt at $([System.Datetime]::Now.ToString("dd/MM/yy HH:mm:ss"))"
Get-ChildItem -Path "$OldLocation" -Recurse -Include $Type | ForEach-Object -Begin { $Counter = 1 } -Process { Rename-Item $_ -NewName "Split$Counter.txt"; $Counter++}
$originaltotal=(get-childitem $OldLocation\Split*.txt).count
$tempruns=$Runs
$tempfiles=$Files
$finalfolderfiles=[math]::ceiling($originaltotal / [math]::pow($tempFiles, $Runs))
New-Item -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU | Out-Null
New-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -PropertyType DWORD -force | Out-Null
#Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 DWORD
Restart-Service wuauserv | Out-Null
do{
	$finalfiles=[math]::ceiling($originaltotal / [math]::pow($tempFiles, $tempruns))
	$finalfilestotal=$finalfilestotal+$finalfiles
	$tempruns-=1
} while ($tempruns -ne 0)	
$finalfilesrun=0
$Files=$Files-1
do{
	$RCount+=1
	$min=1
	$max=$min+$Files
	$total=(get-childitem $OldLocation\Split*.txt).count
	New-Item -Path (split-path $NewLocation) -Name (split-path $NewLocation -leaf) -ItemType "directory"
	$fcount=0
	do{
		$sfcount=($max-$min)+1
		$fcount+=1
		$finalfilesrun+=1
		$foldertotal=(get-childitem $OldLocation\Split*.txt).count		
		$runfiles=[math]::ceiling($foldertotal / ($tempFiles))
		$percentage=($min / $total) # .tostring("P")
		$percent=$percentage * 100
		$percentagestring=$percentage.tostring("P")
		$pause = (Get-Date).AddDays(35)
		$pause = $pause.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
		$pause_start = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
		
		echo("________________________________________________________________________________")
		echo("Current = Run-$RCount/$Runs, Min-$min, Max-$max, File Count-$sfcount, Current-$fcount, Total Run-$runfiles")
		echo("File = Source-$OldLocation, Destination-$NewLocation, Total To Sort-$total") 
		echo("Total = Total Files-$finalfilesrun, Total Files-$finalfilestotal, Final Folder Files-$finalfolderfiles")
		echo("Run - $percentagestring, Total - $($($finalfilesrun / $finalfilestotal).tostring("P")) - $([System.Datetime]::Now.ToString("dd/MM/yy HH:mm:ss"))")
		echo("Disabling and postponing Windows Update until $pause")
		
		Write-Progress -ID 0 -Activity "Creating and Sorting Wordlist with Removing Duplicates" -status "This Run Completion:" -percentcomplete $percent 
		Write-Progress -ID 1 -Activity "Total Runs" -status "Total Run Completion:" -percentcomplete (($RCount / $Runs) * 100)
		Write-Progress -ID 2 -Activity "Total Files" -status "Total File Completion:" -percentcomplete (($finalfilesrun / $finalfilestotal) * 100)
		
		Stop-Service BITS | out-null
		Stop-Service wuauserv | out-null
		Stop-Service CryptSvc | out-null
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesStartTime' -Value $pause_start

		if($min+$Files -gt (get-childitem $OldLocation\Split*.txt).count){$min=$total} else {write-output "$min-$max to Split$fcount at $([System.Datetime]::Now.ToString("dd/MM/yy HH:mm:ss"))"}
		for ($i=$min; $i -lt $max+1; $i++){(Get-Content -Path $OldLocation\Split$i.txt) | out-File $NewLocation\Split$fcount.txt -append}
		write-output "Removing special characters at $([System.Datetime]::Now.ToString("dd/MM/yy HH:mm:ss"))" 
		(Get-Content -Path $NewLocation\Split$fcount.txt) -Replace("[^`\w]","`n") | out-File $NewLocation\Split$fcount.txt
		write-output "Adding the same without numbers at $([System.Datetime]::Now.ToString("dd/MM/yy HH:mm:ss"))"
		(Get-Content -Path $NewLocation\Split$fcount.txt) -Replace("[`\d]","") | out-File $NewLocation\Split$fcount.txt -append
		write-output "Removing duplicates and sorting at $([System.Datetime]::Now.ToString("dd/MM/yy HH:mm:ss"))"
#		Get-Content -Path "$NewLocation\Split$fcount.txt" | Sort-Object | Get-Unique | Set-Content -Path "$NewLocation\Split$fcount.txt"
		$text = Get-Content "$NewLocation\Split$fcount.txt" -Raw
		$words = [regex]::Split($text, '\W+') | Where-Object { $_ }
		$uniqueWords = [System.Collections.Generic.HashSet[string]]::new(
			[string[]]$words,
			[System.StringComparer]::OrdinalIgnoreCase
		)
		$uniqueWords | Sort-Object | Set-Content "$NewLocation\Split$fcount.txt"


		if(($min) -lt $total){ 
			if(($min+$Files) -ge $total){$min=$total} else {$min=$min+$Files+1}
			if(($max+$Files) -ge $total){$max=$total} else {$max=$min+$Files}
		} else {
			$min = $total
		}
	} while ($min -lt $total)

Get-Content -Path "$NewLocation\Split$fcount.txt" | Sort-Object | Get-Unique | Set-Content -Path "$NewLocation\Split$fcount.txt"

	echo("================================================================================")
	echo("End of Run - $percentagestring - $($percentage.tostring("P")) - $([System.Datetime]::Now.ToString("dd/MM/yy HH:mm:ss"))")
	$RenameLocation = $RenameLocation + '.old'
	rename-item -path $OldLocation -newname $RenameLocation
	rename-item -path $NewLocation -newname $OldLocation
	Get-ChildItem -Path "$OldLocation" -Recurse -Include *.txt | ForEach-Object -Begin { $Counter = 1 } -Process { Rename-Item $_ -NewName "a$Counter.txt" ; $Counter++ }
	Get-ChildItem -Path "$OldLocation" -Recurse -Include *.txt | ForEach-Object -Begin { $Counter = 1 } -Process { Rename-Item $_ -NewName "Split$Counter.txt" ; $Counter++ }
} while ($RCount -ne $Runs)
Stop-Transcript
rename-item -path $LogFile -newname '$([System.Datetime]::Now.ToString("dd-MM-yy"))").log'
