Set-ExecutionPolicy -executionpolicy bypass -scope Process -force
$CurrentScriptVer="1.1.5"
$host.UI.RawUI.WindowTitle = "The Little Tech Helper Script $CurrentScriptVer"

$Folder='c:\LTH'
$Time="03:00"
$CurrentDate=(Get-date).ToString('MM-dd-yyyy')
$FutureDate=(Get-date).AddDays(1).ToString('MM-dd-yyyy')
$Transcript=$Folder + "\Transcript.log"
$Users= get-childitem -directory -path "c:\users"; 
$Global:VSSChangeLog 
$Script=invoke-webrequest -uri https://raw.githubusercontent.com/MicrosoftSavvy/Released/refs/heads/main/LittleTechHelper.ps1
$ScriptRaw=(($Script.rawcontent).split("`n")).replace("`r",'') | Select-Object -skip 26
$DownloadScriptVer=(($ScriptRaw | Where-Object { $_ -match "CurrentScriptVer" }) -replace "[^\d.]","")[0]
$Drives=(get-psdrive -PSProvider 'FileSystem').root
if(!(test-path $Folder)){New-Item -Path $Folder -ItemType "directory"}

function PendingReboot {
	$CurrentStatus = "Checking if a reboot is pending" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}}
	if (Get-ChildItem 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -EA Ignore) { return $true }
	if (Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -EA Ignore) { return $true }
	if (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA Ignore) { return $true }
	try {$util = [wmiclass]'\\.\root\ccm\clientsdk:CCM_ClientUtilities'
	$status = $util.DetermineIfRebootPending() 
	if (($status -ne $null) -and $status.RebootPending) {return $true; $Status.items.add("Restart is pending")}} catch { }; return $false
} 

function UpdateModules {
	Install-PackageProvider -Name NuGet -Force | Out-Null
	Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery | Out-Null
	Repair-WinGetPackageManager
	Install-Module PSWindowsUpdate -Force -Repository PSGallery | Out-Null
	Import-Module PSWindowsUpdate
	$Winget = ((gci "C:\Program Files\WindowsApps" -Recurse -File | Where-Object { ($_.fullname -match 'C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_' -and $_.name -match 'winget.exe') } | sort fullname -descending | %{$_.FullName}) -Split [Environment]::NewLine)[0]
	&"$Winget" source update
}

function Pull-Logs {
	
	if ($TXTMIN.Text -ne $null) {$MinutesBack=$TXTMIN.Text}else {$MinutesBack=180}
	$SystemLog=$Folder+"\System.log"
	$ApplicationLog=$Folder+"\Application.log"
	$SecurityLog=$Folder+"\Security.log"
	$StartLogDate=(Get-date).addminutes(-$MinutesBack).tostring('yyyy-MM-dd HH:mm:ss')
	$CBSLog=$Folder + "\CBSLog.log"
	$DISMLog=$Folder + "\DISMLog.log"
	
	$CurrentStatus = "Pulling errors from log files for the last $MinutesBack minutes" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}}
	
	$System = ((Get-EventLog -LogName System -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "Error" -ErrorAction SilentlyContinue) | Format-Table -AutoSize -Wrap)
	$Application = ((Get-EventLog -LogName Application -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "Error" -ErrorAction SilentlyContinue) | Format-Table -AutoSize -Wrap)
	$Security = ((Get-EventLog -LogName Security -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "FailureAudit"  -ErrorAction SilentlyContinue) | Format-Table -AutoSize -Wrap)
	if (!($System -eq $null)){Out-File -FilePath $SystemLog -InputObject (Get-EventLog -LogName System -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "Error" | Format-Table -AutoSize -Wrap)}
	if (!($Application -eq $null)){Out-File -FilePath $ApplicationLog -InputObject (Get-EventLog -LogName Application -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "Error" | Format-Table -AutoSize -Wrap)}
	if (!($Security -eq $null)){Out-File -FilePath $SecurityLog -InputObject (Get-EventLog -LogName Security -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "FailureAudit" | Format-Table -AutoSize -Wrap)}
	$DISMContents=get-content "c:\Windows\Logs\DISM\DISM.log"  | Where-Object { $_ -GE $StartLogDate} 
	$DISMErr=$DISMContents | Select-String 'Err'
	$DISMErrors=$DISMContents | Select-String -SimpleMatch 'ERROR'
	if($DISMErrors -ne $null){
		Out-File -FilePath $DISMLog -InputObject $DISMErrors.line
	} else {
		if($DISMErr -ne $null){
		Out-File -FilePath $DISMLog -InputObject $DISMErr.line
		} else {
	}
}
	$CBSContents=get-content "c:\Windows\Logs\CBS\CBS.log" | Where-Object { $_ -GE $StartLogDate} 
	$CBSErr=$CBSContents | Select-String 'Err'
	$CBSErrors=$CBSContents | Select-String -SimpleMatch 'ERROR'
	if($CBSErrors -ne $null){
		Out-File -FilePath $CBSLog -InputObject $CBSErrors.line		
		} else {
			if($CBSErr -ne $null){
			Out-File -FilePath $CBSLog -InputObject $CBSErr.line		
			} else {
			}
		}
}

function VSS {
	$CurrentStatus = "Checking to see if VSS is enabledl enabling and scheduling" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}}
	$VSSLog=$Folder+"\VSS.log"
	foreach ($DriveLetter in $Drives){
	$drive=$DriveLetter.replace(":\","")
	if (!(Get-ScheduledTask | Where-Object { $_.TaskName -like '*Shadow*' } | Select-Object TaskName, State)){
		$Global:VSSChangeLog = @()
		$vssService = Get-WmiObject -Class Win32_Service -Filter "Name='VSS'"
		if ($vssService.StartMode -ne 'Auto') {
			$vssService.ChangeStartMode('Automatic')
			$Global:VSSChangeLog = $Global:VSSChangeLog + "Changed VSS service to Automatic start.`n"
			} else {
			$Global:VSSChangeLog = $Global:VSSChangeLog + "VSS service set to Automatic start.`n"			
		}
		Start-Service -Name VSS
		$Global:VSSChangeLog = $Global:VSSChangeLog +  "Started VSS service."
		(Get-WmiObject -List Win32_ShadowCopy).Create($driveLetter, "ClientAccessible")
		$Global:VSSChangeLog = $Global:VSSChangeLog +  "Enabled Shadow Copy for $driveLetter."
		$action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
		-Argument " -windowstyle hidden -command (Get-WmiObject -List Win32_ShadowCopy).Create(`'$driveLetter`', `'ClientAccessible`')"
		$trigger1 = New-ScheduledTaskTrigger -Daily -At 7AM
		$trigger2 = New-ScheduledTaskTrigger -Daily -At 12PM
		$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries 
		Register-ScheduledTask -Action $action -Trigger $trigger1, $trigger2 -Settings $settings  `
		-TaskName "ShadowCopy Creation for Drive $drive" `
		-Description "Task for creating Shadow Copies" `
		-RunLevel Highest
		$Global:VSSChangeLog = $Global:VSSChangeLog + "Scheduled Task for creating Shadow Copies at 7AM and 12PM for drive $driveLetter is set."
		if ($Status -ne $null) {$Status.items.add($Global:VSSChangeLog)}else {Write-Host $Global:VSSChangeLog -foregroundcolor Green}
		if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
} else {$Global:VSSChangeLog = "VSS Already Enabled on $Drive.`n"; if ($Status -ne $null) {$Status.items.add($Global:VSSChangeLog)}else {Write-Host $Global:VSSChangeLog -foregroundcolor Green}
}
}
	if (!($Global:VSSChangeLog -eq $null)){Out-File -FilePath $VSSLog -InputObject $Global:VSSChangeLog}
}

function RunDISM {
	$CurrentStatus = "Checking System Files" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$DismScanResults=(Repair-WindowsImage -Online -scanhealth -LogPath:$Folder\CurrentRunDISM.log -loglevel:1)
	if(!$DismScanResults.imagehealthstate -like 'Healthy'){write-host "Attempting To Restore System Health" -foregroundcolor Green}
	$DismRestoreResults=(Repair-WindowsImage -online -restorehealth -LogPath:$Folder\CurrentRunDISM.log -loglevel:1)
	Write-host "File System Status: "$DismRestoreResults.imagehealthstate 
	if(!$DismRestoreResults.imagehealthstate -like 'Healthy'){write-host 'Need to download source files' -foregroundcolor Yellow}
}

function DownloadSource {
$Ver=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild + '.' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
$OSNumber=((Get-WmiObject -Class Win32_OperatingSystem).name).split()[1] + " " + ((Get-WmiObject -Class Win32_OperatingSystem).name).split()[2]
$OSType=((Get-WmiObject -Class Win32_OperatingSystem).name).split()[3]
$OSType=$OSType.substring(0, 3)
$OS=$OSNumber + '*'
$OSName=$OSNumber + " " + $OSType
$URL="https://uupdump.net/known.php?q=" + $Ver
$ISODownload=Invoke-WebRequest -uri $URL
$ISOList=($ISODownload.links)
$temp='*A href=`"selectlang.php?id=*'
$ISOList=($ISOList | Where-Object { $_.outerhtml -like $temp -and $_.innerhtml -like $OS }).outerhtml
$ISOL=$ISOList.replace('<A href="selectlang.php?id=','')
$ISOL=$ISOL -replace('"',' ')
$ID=$ISOL.split()[0]
$DL='https://uupdump.net/get.php?id='+$ID+'&pack=en-us&edition=core;professional'
$FindFile=Invoke-WebRequest -uri $DL
$DownLoad=($FindFile.links | Where-Object {$_.outertext -like "$OSType*"}).outerhtml
$DLF=$DownLoad.replace('<A href=','')
$DLF=$DLF -replace '"',' '
$File2Download=$DLF.Split()[1]
$FN=$DLF.Split()[2]
$FileName=$FN.substring(1)
$File2Download=$File2Download.replace('amp;','')
$File=$Folder+'\'+$FileName
	$CurrentStatus = "Downloading Source System Files" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	((New-Object System.Net.WebClient).DownloadFile($File2Download,$File))
	do{$CopySize=(Get-ChildItem $File).length
	start-sleep (5)} until (((Get-ChildItem $File).length) -match $CopySize)
	ConvertSource
}

function DISMRepairSource {
	$CurrentStatus = "Running Repairs with Source Files" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$IWIM="$Folder\install.wim"
	if (test-path $IWIM){
		DISM -online -source:$Folder\install.wim -index:1 -restorehealth -LogPath:$Folder\CurrentRunDISM.log -loglevel:1
	} else {
		Repair-WindowsImage -online -source:$File -restorehealth -LogPath:$Folder\CurrentRunDISM.log -loglevel:1
	}
}

function ConvertSource {
	$CurrentStatus = "Extracting index and Converting to Install.WIM" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$Index=(Dism /Get-ImageInfo /ImageFile:$File /Name:$OSName)[6]
	$Index=$Index -replace 'Index : ',''
	$WIM=(Dism /Export-image /SourceImageFile:$File /SourceIndex:$Index /DestinationImageFile:$Folder\install.wim /Compress:max /CheckIntegrity)
	$WIM | Select -last 5
	if(!$WIM -like 'The operation completed successfully.'){
		write-host 'Failed to convert file, try to run as is' -foregroundcolor Red
	} else {
			if (Test-Path $Folder\install.wim){
		write-host 'File converted successfully - Running Repair' -foregroundcolor Green
	}
	}
}

function CleanUp {
	$CurrentStatus = "Cleaning up downloaded system files" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	Remove-Item -Path $Folder\*.esd, $Folder\*.wim, $Folder\*.exe, $Folder\*.ps1, $Folder\*.txt
}

function RunSFC {
	$CurrentStatus = "Running System File Checker" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$SFCResults=(sfc /scannow)
	if ($SFCResults -eq 'Windows Resource Protection did not find any integrity violations.'){
	$CurrentStatus = "SFC is Completed" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	} else {
	$CurrentStatus = "SFC had issues" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Red}
	}
}

function RunCHK {
	$CurrentStatus = "Running CheckDisk Scan" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$Scan=(Repair-Volume -DriveLetter C -Scan)
	if(!$Scan -like 'NoErrorsFound'){
		Write-host "Running Quick CheckDisk Repair" -foregroundcolor Green
		$QR=(Repair-Volume -DriveLetter C -SpotFix -verbose)
	}
	if(!$QR -like 'NoErrorsFound'){
		Write-host "Running Full CheckDisk Repair" -foregroundcolor Green
		Repair-Volume -DriveLetter C -OfflineScanAndFix -verbose
	}
}

function ReRegDLLs($DLLLog) {
	$CurrentStatus = "Re-Registering DLLs in System32 and SYSWOW64" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$DLLRLog=$Folder + "\DLLReRegister.log"
	$Global:DLLLog
	$DLLFolders='c:\Windows\System32','c:\Windows\Syswow64'
	ForEach($DLLF in $DLLFolders){
		$FCount=0
		$DLLList=(get-childitem $DLLF\*.dll).fullname
		$DLLList=$DLLList+(get-childitem $DLLF\*.ocx).fullname
		foreach($DFile in $DLLList){
			c:\windows\system32\regsvr32 /s %DFile
			$FCount+=1
			$Percent=(($FCount/$DLLList.count) * 100)
			write-progress -Activity "Re-Registering DLLs" -PercentComplete $Percent
		}
		$Global:DLLLog=$($Global:DLLLog + $DLLList)
		Write-Progress -Completed -Activity " "
	}
	if (!($Global:DLLLog -eq $null)){Out-File -FilePath $DLLRLog -InputObject $Global:DLLLog}
}

function ShowVaribles {
	$VaribleExport=$Folder + "\Varibles.log"
	$CurrentStatus = "Varibles being exported to " + $VaribleExport 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	(Get-Variable | format-table -autosize -wrap) | out-file $VaribleExport
}

function ScheduleRestart {
	$CurrentStatus = "Checking if restart is pending and scheduling for $Time" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}}
	$RunAfter=$Folder+"\Repair.ps1"
	if (PendingReboot -eq "True") {
		$RestartSchedule=(schtasks /Create /SC ONCE /TN "ScheduledRestart" /TR "shutdown /r /f /t 0" /SD $FutureDate /ST $time /F /Z /rl HIGHEST /ru System /V1)
		if (!(Get-ScheduledTask | Where-Object { $_.TaskName -like '*ScheduledRestart*' } | Select-Object TaskName, State)){$RestartSchedule}
		(((get-content $PSCommandPath) | select-object -skiplast 1).replace('GUI #','AfterStartUp'),'').replace('[void]$form.ShowDialog()','') | Out-File -FilePath $RunAfter
		if (!(Get-ScheduledTask | Where-Object { $_.TaskName -match 'RepairAfterRestart' } | Select-Object TaskName, State)){
		Register-ScheduledTask -TaskName "RepairAfterRestart" -InputObject (
		(
			New-ScheduledTask -Action (
				(New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy ByPass -file $Folder\Repair.ps1"),
				(New-ScheduledTaskAction -Execute powershell -Argument "-ExecutionPolicy ByPass -Command `"Unregister-ScheduledTask -TaskName 'RepairAfterRestart' -Confirm:`$false`"")
			) -Trigger (
				New-ScheduledTaskTrigger -AtStartup
			)  -Principal (
			New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
			)
		)
	)
		}
	$CurrentStatus = "Task: ScheduledRestart scheduled for " + $FutureDate + " " + $Time
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)} else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	} else {
	$CurrentStatus = "No Restart Needed"
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)} else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	if ($CBCleanUp.Checked) { CleanUp }
	}
}

function Runtimes {
	$CurrentStatus = "Downloading and Installing Runtimes" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$NRTLog=$Folder+"\Runtime.log"
	#$RTLinks='https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170'
	$Runtimes='https://aka.ms/vs/17/release/vc_redist.x86.exe','https://aka.ms/vs/17/release/vc_redist.x64.exe','https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe','https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe'
	UpdateModules
	foreach($Rt in $Runtimes){
		$RtFN = ($Folder + '\' + (($Rt.replace('/',' ')).split() | Where-Object {$_ -like "*.exe"}))
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		((New-Object System.Net.WebClient).DownloadFile($Rt,$RtFN))
		start-process -filepath $RtFN -ArgumentList "-quiet","-norestart"
	}
	$n=5
	do {
		$DNR="Microsoft DotNet Runtime " + $n
		$CurrentNetRuntime=winget install --id=Microsoft.DotNet.Runtime.$n  -e --silent --accept-source-agreements --include-unknown --verbose
		$NetRuntime=$NetRuntime + $DNR + $CurrentNetRuntime
		$n+=1
	} until ($n -gt 9)
	$Global:NetRuntime=switch ($NetRuntime) {{ $_.length -ge 9 } { $_ }}
	if (!($Global:NetRuntime -eq $null)){Out-File -FilePath $NRTLog -InputObject $Global:NetRuntime}
}

function Update {
	$CurrentStatus = "Running Updates on Windows and Microsoft Store Apps" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	UpdateModules
	$WinGetLog=$Folder+"\AppUpdate.log"
	Install-WindowsUpdate -MicrosoftUpdate -NotCategory 'feature pack','driver','upgrades' -AcceptAll -Install -IgnoreReboot -Verbose
	Winget upgrade --all --silent --accept-source-agreements  --include-unknown --verbose
	$Global:WinGet=switch ($WinGet) {{ $_.length -ge 9 } { $_ }}
	if (!($Global:WinGet -eq $null)){Out-File -FilePath $WinGetLog -InputObject $Global:WinGet}
}

function RemoveBadDevices {
	$CurrentStatus = "Removing Problematic Devices" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	 foreach ($dev in (Get-PnpDevice | Where-Object {$_.Status -notmatch "OK" -and $_.Present -like "True" -and $_.InstanceId -notmatch "STORAGE" -and $_.Class -notmatch "SmartCardFilter"})) {
		 write-host Removing $dev.Name -foregroundcolor Green
		 &"pnputil" /remove-device $dev.InstanceId
		 }
}

function AppUpdate {
	if ($DownloadScriptVer -gt $CurrentScriptVer){
		$CurrentStatus = "Downloading Update" 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		$ScriptRaw | Out-File -FilePath $PSCommandPath -force -encoding utf8
		$form.dispose()
		$form.close()
		powershell -executionpolicy bypass -file $PSCommandPath
	}
}

function FreeUpSpace {
	$CurrentStatus = "Freeing up disk space" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$hardwaretype=(Get-WmiObject -Class Win32_ComputerSystem -Property PCSystemType).PCSystemType
	$FUSFolders=@('c:\ESD','C:\Windows\SoftwareDistribution\Download','c:\ProgramData\Adobe\Temp','c:\$GetCurrent','c:\recovery','c:\windows10upgrade','C:\WINDOWS\SystemTemp\ScreenConnect') 
	Repair-WindowsImage -Online -StartComponentCleanup -ResetBase
		foreach ($CurrentFUSList in $FUSFolders){
		if(Test-Path $CurrentFUSList) {
			takeown /f $CurrentFUSList /R /A /D N
			cacls $CurrentFUSList /t /c /e /g system:f
			cacls $CurrentFUSList /t /c /e /g everyone:f
			icacls $CurrentFUSList /inheritance:e
			attrib $CurrentFUSList -r -h -a -s /d /s
			remove-item -path $CurrentFUSList -recurse -ErrorAction SilentlyContinue
		}
	}
	remove-item -path $env:temp\* -recurse -ErrorAction SilentlyContinue
	remove-item -path c:\$Recycle.Bin\* -recurse -ErrorAction SilentlyContinue
	Set-Service -Name "wsearch" -StartupType Disabled
	Stop-Service -Name "wsearch"
	Net stop wsearch
	EsentUtl.exe /d %AllUsersProfile%\Microsoft\Search\Data\Applications\Windows\Windows.edb
	Set-Service -Name "wsearch" -StartupType auto
	Start-Service -Name "wsearch"
	If ($hardwaretype -ne 2){powercfg -h off}else{}
	foreach ($Profile in $Users){
		remove-item -path c:\windows\temp\* -force -recurse -confirm:$false -ErrorAction SilentlyContinue
		remove-item -path c:\users\$profile\appdata\local\temp\* -force -recurse -confirm:$false -ErrorAction SilentlyContinue
	}
	cleanmgr /d c: /verylowdisk /autoclean
	compact /c /s:c:\windows\installer /a /i /f /q
}

function ScheduledTasks {
	$CurrentStatus = "Getting Scheduled Tasks that run as a user" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$CurrentTime=(Get-date).tostring('yyyy-MM-dd HH:mm:ss')
	$USTLog=$Folder+"\ScheduledTasks-User.log"
	$TSTLog=$Folder+"\ScheduledTasks-Timed.log"
	$UserScheduledTasks=(Get-ScheduledTask | Where-Object {$_.Principal.UserId -notlike "NT AUTHORITY*" -and $_.Principal.UserId -notlike "SYSTEM" -and $_.Principal.UserId -notlike "LOCAL SERVICE" -and $_.Principal.UserId -notlike "NETWORK SERVICE" -and $_.Principal.UserId -notlike $null} | Select-Object @{Name="Run As";Expression={ $_.principal.userid } }, TaskPath, TaskName)
	$TimeScheduledTasks=(Get-ScheduledTask | ForEach-Object {
		$task = $_
		foreach ($trigger in $task.Triggers) {
		$startBoundary = $null
	try {
		$startBoundary = [datetime]$trigger.StartBoundary
	} catch {}
	if ($startBoundary -and $startBoundary -gt $CurrentTime) {
	[PSCustomObject]@{
	TaskName = $task.TaskName
	TaskPath = $task.TaskPath
	'Next Run Time' = $startBoundary.ToString("yyyy-MM-dd HH:mm:ss")
	}
	}
	}
	} | Format-Table @{Label="TaskName";Expression={$_.TaskName};Width=40}, @{Label="TaskPath";Expression={$_.TaskPath};Width=50}, @{Label="Next Run Time";Expression={$startBoundary.ToString('yyyy-MM-dd HH:mm:ss')};Width=20} -wrap)
	if (!($UserScheduledTasks -eq $null)){Out-File -FilePath $USTLog -InputObject $UserScheduledTasks}
	if (!($TimeScheduledTasks -eq $null)){Out-File -FilePath $TSTLog -InputObject $TimeScheduledTasks}
}
function PrivateNetwork {
	$CurrentStatus = "Setting Network as Private" 
	$Network=(Get-NetConnectionProfile).Name
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$Global:NetworkOld = (Get-NetConnectionProfile)
	$Global:NetworkNew = (Set-NetConnectionProfile -Name $Network -NetworkCategory Private)
	$NetworkLog=$Folder+"\Network.log"
	if (!($Network -eq $null)){Out-File -FilePath $NetworkLog -InputObject $Network}
	if (!($Global:NetworkOld -eq $null)){Out-File -FilePath $NetworkLog -InputObject $Global:NetworkOld -append}
	if (!($Global:NetworkNew -eq $null)){Out-File -FilePath $NetworkLog -InputObject $Global:NetworkNew -append}
}

function PC-Rename {
	$CurrentStatus = "Renaming PC" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	if ($CBPCRST.checked -eq "True"){
		Rename-Computer -ComputerName (Get-WmiObject win32_COMPUTERSYSTEM).Name -NewName (Get-WmiObject Win32_BIOS).serialnumber -force
	} else {
		Rename-Computer -ComputerName (Get-WmiObject win32_COMPUTERSYSTEM).Name -NewName $TXTPCR.text -Force
}
}

function RemoveDeviceGroup {
	$CurrentStatus = "Removing All Drivers for " + $DDDevices.Text 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$DeviceClass=$DDDevices.Text
	$Directory=$Folder + "\DriverExport"
	if(!(test-path $Directory)){New-Item -Path $Directory -ItemType "directory"}
	$OEMList = (gwmi win32_PnPSignedDriver | ? DeviceClass -eq $DeviceClass | Select InfName)
	$MediaList = (gwmi win32_PnPSignedDriver | ? DeviceClass -eq $DeviceClass | Select DeviceID)
	$MediaDevice = $Folder + "\MediaDevicesRemoved.log"
	$MediaDeviceList = $Folder + "\MDL.txt"
	$LIST = $Folder + "\RemovedFiles.log"
	$LISTFULL = $Folder + "\listfull.txt"
	PNPUTIL /export-driver * $Directory
	write-output $MediaList > $MediaDevice
	(Get-Content $MediaDevice | Select-Object -Skip 3) | Select-Object -SkipLast 2 | Set-Content $MediaDeviceList
	(Get-Content -path $MediaDevice) -Replace(" ","") | out-file $MediaDeviceList
	foreach($DEVID in [System.IO.File]::ReadLines($MediaDeviceList)){
	PNPUTIL /disable-device "$DEVID"
	pnputil /remove-device "$DEVID"
	}
	write-output $OEMList > $LISTFULL
	(Get-Content $LISTFULL | Select-Object -Skip 3) | Select-Object -SkipLast 2 | Set-Content $LIST
	(Get-Content -path $LIST) -Replace(" ","") | out-file $LIST  -force -encoding utf8
	foreach($File in [System.IO.File]::ReadLines("$Folder\RemovedFiles.log")){
	PNPUTIL /delete-driver $File
	}
}

function EnablePowerOptions {
	$CurrentStatus = "Enabling all options in Power Settings" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}}
	$powerSettingTable = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerSetting
	$powerSettingInSubgroubTable = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerSettingInSubgroup
	Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerSettingCapabilities | ForEach-Object {
		$tmp = $_.ManagedElement
		$tmp = $tmp.Remove(0, $tmp.LastIndexOf('{') + 1)
		$tmp = $tmp.Remove($tmp.LastIndexOf('}'))
		$guid = $tmp
		$s = ($powerSettingInSubgroubTable | Where-Object PartComponent -Match "$guid")
		if (!$s) {
		return
		}
		$tmp = $s.GroupComponent
		$tmp = $tmp.Remove(0, $tmp.LastIndexOf('{') + 1)
		$tmp = $tmp.Remove($tmp.LastIndexOf('}'))
		$groupguid = $tmp
		$s = ($powerSettingTable | Where-Object InstanceID -Match "$guid")
		$descr = [string]::Format("# {0} enabled", $s.ElementName)
		Write-Output $descr
		$keyPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\$groupguid\$guid"
		$valueName = "Attributes"
		$outFile = $Folder + '\OriginalPower' + $CurrentDate + '.reg'
		$tempFile = New-TemporaryFile
		$null = reg.exe export $keyPath $tempFile /y
		$null = (Get-Content -Raw $tempFile) -match '(?s)^(.+?\])\r\n(.+?)\r\n(?:\r\n|\z)'
		Remove-Item $tempFile
		$headerLinesBlock = $Matches[1]
		$valueLinesBlock = $Matches[2]
	$valueDataPair = $Matches[0]
	$headerLinesBlock, $valueDataPair | out-file -Encoding Unicode $outFile -append
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\$groupguid\$guid" -Name "Attributes" -Value 00000002 -Type DWORD
  }
}

function FixTime {
	[CmdletBinding()]
	param (
		[Parameter()]
		[int]
		$Max = 2,
		[Parameter()]
		[string]
		$NtpServer ="pool.ntp.org"
	)
	begin {}
	process {
		$CurrentStatus = "Using NTP Server($NtpServer) to get time." 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
		$TimeSample = w32tm.exe /StripChart /Computer:"$NtpServer" /DataOnly /Samples:1
		$Diff = $($($TimeSample | Select-Object -Last 1) -split ', ' | Select-Object -Last 1)
		$TimeScale = $Diff -split '' | Select-Object -Last 1 -Skip 1
		$Diff = switch ($TimeScale) {
			"s" { [double]$($Diff -replace 's') / 60 }
			"m" { [double]$($Diff -replace 'm') }
			"h" { [double]$($Diff -replace 'h') * 60 * 60 }
			"d" { [double]$($Diff -replace 'd') * 60 * 60 * 24 }
			Default {}
		}
		if ($Diff -lt 0) {
			$Diff = 0 - $Diff
		}
		$CurrentStatus = "Time Difference between NTP server and local system: $($([Math]::Round($Diff,2))) minutes"
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
		if ($Diff -gt $Max) {
			$CurrentStatus = "Time if off - Setting up NTP sync"
			if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
			if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
			w32tm /config /syncfromflags:manual /manualpeerlist:"time-a-g.nist.gov time-b-g.nist.gov time-c-g.nist.gov"
			w32tm /resync
		} else {
			$CurrentStatus = "Time is good - skipping"
			if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
			if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
		}
		Set-ItemProperty -Path 'HKLM:\\SYSTEM\CurrentControlSet\Services\tzautoupdate' -Name Start -Value 3
		Set-ItemProperty -Path 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name Value -Value Allow
		Set-Service -Name "tzautoupdate" -StartupType Automatic
		Set-Service -Name "W32Time" -StartupType Automatic
		Start-Service -Name "tzautoupdate"
		Start-Service -Name "W32Time"
	}
}

function Run-Repairs {
	RunDISM
	if(!$DismRestoreResults.imagehealthstate -like 'Healthy'){DownloadSource; ConvertSource; DISMRepairSource}
	RunSFC
	RunCHK
	Runtimes
	ReRegDLLs
	Update
	PrivateNetwork
	FixTime
	CleanUp
	ScheduledTasks
	FreeUpSpace
	ShowVaribles
	RemoveBadDevices
	Pull-Logs
	ScheduleRestart
}

function Spooler {
		$CurrentStatus = "Clearing spooler folder." 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$Spool="C:\Windows\System32\Spool"
	$Spooler="C:\Windows\System32\Spool\Printers"
	$NewOwner = New-Object System.Security.Principal.NTAccount("BUILTIN\Administrators")
	$NewUser = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
	$ACLSpool=get-acl $Spool
	$ACLSpool.SetOwner($NewOwner)
	$ACLSpool.AddAccessRule($NewUser)
	Set-Acl -Path $Spool -AclObject $ACLSpool
	$ACLSpooler=get-acl $Spooler
	$ACLSpooler.SetOwner($NewOwner)
	$ACLSpooler.AddAccessRule($NewUser)
	Set-Acl -Path $Spooler -AclObject $ACLSpooler
	stop-service Spooler
	remove-item -path $Spooler\*.* -force
	start-service Spooler
}

function AfterStartUp {
	RunDISM
	if(!$DismRestoreResults.imagehealthstate -like 'Healthy'){DownloadSource; ConvertSource; DISMRepairSource}
	RunSFC
	CleanUp
}

function ServiceOwner {
	$ServiceToChange=$ServiceList.text
	$CurrentStatus = "Setting permissions for service $ServiceToChange." 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$Service = Get-Service -Name $ServiceToChange
	$acl = Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
	$newOwner = New-Object System.Security.Principal.NTAccount("Administrators")
	$acl.SetOwner($newOwner)
	Set-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)" -AclObject $acl
	$VarD=$null
	$VarS=$null
	$ResultsD=$null
	$ResultsS=$null
	$AddPermissions="(A;;CCDCLCSWRPWPDTLORC;;;BA)"
	$VarAccount="BA"
	[string]$RawResults=sc.exe sdshow $Service
	$RegexPatternALL='(D:)(\(.*\))(S:)(\(.*\))|(S:)(\(.*\))|(D:)(\(.*\))'
	$RawResults -match $RegexPatternALL | out-null
	if ($null -eq $matches[1]){
		$VarD=$Matches[8]
	} else {
		$VarD=$Matches[2]
	}
	if ($null -eq $Matches[3]) {
		$VarS=$Matches[6]
	} else {
		$VarS=$Matches[4]
	}
	if ($null -ne $VarD){
		[array]$ResultsD=$VarD -split '\)\(' | foreach-object {$_ -replace "\(", ""} | foreach-object {$_ -replace "\)", ""}
	}
	if ($null -ne $VarS){
		[array]$ResultsS=$VarS -split '\)\(' | foreach-object {$_ -replace "\(", ""} | foreach-object {$_ -replace "\)", ""}
	}
	Write-Host "Permissions for $ServiceToChange" -foregroundcolor Green
	Write-Host "`nD:" -foregroundcolor Green
	Write-Host $ResultsD -foregroundcolor Green
	Write-Host "`nS:" -foregroundcolor Green
	Write-Host $ResultsS -foregroundcolor Green
	$ExistingPermissions=$null
	if ($null -ne $ResultsD){
		$ExistingPermissions=$ExistingPermissions + "D:"
		for ($i=0; $i -lt $ResultsD.count; $i++) {
			$ExistingPermissions=$ExistingPermissions + "(" + $ResultsD[$i] + ")"
		}
	}
	if ($null -ne $ResultsS){
		$ExistingPermissions=$ExistingPermissions + "S:"
		for ($i=0; $i -lt $ResultsS.count; $i++) {
			$ExistingPermissions=$ExistingPermissions + "(" + $ResultsS[$i] + ")"
		}
	}
	Write-Host "`nParsed permissions:" -foregroundcolor Green
	Write-Host $ExistingPermissions -foregroundcolor Green
	Write-Host "`nOriginal permissions:" -foregroundcolor Green
	Write-Host $RawResults.trim() -foregroundcolor Green
	if ($ExistingPermissions -eq $RawResults.trim()) {
	$CurrentStatus = "`nCorrectly identified existing permissions."
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	$CurrentStatus = "`nBuilding new permissions string...(In Transcript)"
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	
	$NewPermissions=$null
			if ($null -ne $ResultsD){
				$NewPermissions=$NewPermissions + "D:"
				for ($i=0; $i -lt $ResultsD.count; $i++) {
					$NewPermissions=$NewPermissions + "(" + $ResultsD[$i] + ")"
				}
				$NewPermissions=$NewPermissions + $AddPermissions
			}
        if ($null -ne $ResultsS){
            $NewPermissions=$NewPermissions + "S:"
            for ($i=0; $i -lt $ResultsS.count; $i++) {
                $NewPermissions=$NewPermissions + "(" + $ResultsS[$i] + ")"
            }
        }
        write-output "`nNew permissions string will be:"
        $NewPermissions
        $FixedService=sc.exe sdset $service $NewPermissions
$RawResults -match $RegexPatternALL | out-null
if ($null -eq $matches[1]){
    $VarD=$Matches[8]
} else {
    $VarD=$Matches[2]
}
if ($null -eq $Matches[3]) {
    $VarS=$Matches[6]
} else {
    $VarS=$Matches[4]
}
if ($null -ne $VarD){
    [array]$ResultsD=$VarD -split '\)\(' | foreach-object {$_ -replace "\(", ""} | foreach-object {$_ -replace "\)", ""}
}
if ($null -ne $VarS){
    [array]$ResultsS=$VarS -split '\)\(' | foreach-object {$_ -replace "\(", ""} | foreach-object {$_ -replace "\)", ""}
}
write-output "`nD:"
$ResultsD
write-output "`nS:"
$ResultsS
$ExistingPermissions=$null
if ($null -ne $ResultsD){
    $ExistingPermissions=$ExistingPermissions + "D:"
    for ($i=0; $i -lt $ResultsD.count; $i++) {
        $ExistingPermissions=$ExistingPermissions + "(" + $ResultsD[$i] + ")"
    }
}
if ($null -ne $ResultsS){
    $ExistingPermissions=$ExistingPermissions + "S:"
    for ($i=0; $i -lt $ResultsS.count; $i++) {
        $ExistingPermissions=$ExistingPermissions + "(" + $ResultsS[$i] + ")"
    }
}
write-output "`nParsed permissions:"
$ExistingPermissions
write-output "`nOriginal permissions:"
$RawResults.trim()
if ($ExistingPermissions -eq $RawResults.trim()) {
    Write-Output "`nCorrectly identified existing permissions."
        write-output "`nBuilding new permissions string..."
        $NewPermissions=$null
        if ($null -ne $ResultsD){
            $NewPermissions=$NewPermissions + "D:"
            for ($i=0; $i -lt $ResultsD.count; $i++) {
                $NewPermissions=$NewPermissions + "(" + $ResultsD[$i] + ")"
            }
            $NewPermissions=$NewPermissions + $AddPermissions
        }
        if ($null -ne $ResultsS){
            $NewPermissions=$NewPermissions + "S:"
            for ($i=0; $i -lt $ResultsS.count; $i++) {
                $NewPermissions=$NewPermissions + "(" + $ResultsS[$i] + ")"
            }
        }
        write-output "`nNew permissions string will be:"
        $NewPermissions
        $FixedService=sc.exe sdset $service $NewPermissions
		if ($FixedService[2] -eq 'Access is Denied.'){
			$PST2Download='https://download.sysinternals.com/files/PSTools.zip'
			$PSTFiles=$env:temp + "\pstool.zip"
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			((New-Object System.Net.WebClient).DownloadFile($PST2Download,$PSTFiles))
			Expand-Archive -Path $PSTFiles -DestinationPath $env:windir -ErrorAction SilentlyContinue
			$ServiceFixedService=$env:windir + "\psexec.exe -s -h sc.exe sdset $service $NewPermissions"
			$ServiceFixedService[5]
		}
        write-output "Permissions for this account already exist. Please review."
} else {
    write-output "`nUnable to properly parse the permission results. Please review."
}
        write-output "Permissions for this account already exist. Please review."
} else {
    write-output "`nUnable to properly parse the permission results. Please review."
}
}

function NetworkCheck {
$IPGate=((get-netipconfiguration).ipv4defaultgateway).nexthop
$DNSList=(Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)
$PublicDNS='1.1.1.1','8.8.8.8','208.67.222.222'
$PingDomain='google.com'
$PullDomain=Invoke-WebRequest $PingDomain
	$CurrentStatus = "Testing Network Cards" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
if ($PullDomain -ne $null) {
	$CurrentStatus = "Able to connect to $PingDomain" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
}
Try {
	if ((test-connection -computername $IPGate -count 1 -quiet) -eq $True) {
	$CurrentStatus = "Able to ping $IPGate" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	} else {
	$CurrentStatus = "Not able to ping $IPGate" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Red}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
}
	foreach ($DNS in $DNSList) {
		$CurrentStatus = "`nUsing $DNS" 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}		
		if ((test-connection -computername $DNS -count 1 -quiet) -eq $true) {
		Try {
		$Results=((Resolve-DnsName $PingDomain -Server $DNS -Type A -nohostsfile) | ft -autosize)
		if ($Results.length -gt 2){
		$CurrentStatus = "$PingDomain is availble using $DNS" 
		}
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
		} catch {
		$CurrentStatus = "$PingDomain not reachable using current DNS server: $DNS" 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
		Try {
		foreach ($PDNS in $PublicDNS) {
		$Results=((Resolve-DnsName $PingDomain -Server $PDNS -Type A -nohostsfile) | ft -autosize)	
		$CurrentStatus = $Results 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
		}
		} catch {
		$CurrentStatus = "$PingDomain not reachable using DNS server: $PDS" 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	}}}}} catch {
		$CurrentStatus = "Gateway not pingable"
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Red}
		if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
		
	}
}

function ClearBins {
	Remove-item -path 'c:\$Recycle.Bin' -recurse -force
}

function  SecureHost {
	$hostfile="C:\windows\system32\drivers\etc\hosts"
	if ((Select-String -Path $hostfile -Pattern "###Secure Hosts File###" -AllMatches) -ne $null) {$LineCount=(Select-String -Path $hostfile -Pattern "###Secure Hosts File###" -AllMatches).linenumber - 1}
	if ($LineCount -ne $null){$OriginalHost=Get-Content $hostfile | Select -first $LineCount} else {$OriginalHost=Get-Content $hostfile}
	$WebHost = ((invoke-webrequest "https://raw.githubusercontent.com/MicrosoftSavvy/Released/refs/heads/main/SecureHost").rawcontent).split("`n") | select-object -skip 26
	$NewHost=$OriginalHost + $WebHost
	$NewHost | Out-File -FilePath $hostfile -force -encoding utf8
	(gc $hostfile) | ? {$_.trim() -ne "" } | set-content $hostfile
}

function PullWiFiPWDs {
	$WiFiList=$Folder + "\Wi-Fi Passwords.log"
	[array]$WiFiPWs=(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)} | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ "Wi-Fi Network"=$name;Password=$pass }}
	$WiFiPWs | Out-File -FilePath $WiFiList -force -encoding utf8
	$CurrentStatus = (Get-Content $WiFiList) | select -skip 1 | select -skiplast 2
	if ($Status -ne $null) {
		foreach ($Current in $CurrentStatus){
		$Status.items.add($Current)
		}
		}else {
			$CurrentStatus
			}
	if ($Status -ne $null) {
		$Status.items.add("`n")
	}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
}

function NewITPC {
	$SoftwareList = (((invoke-webrequest "https://raw.githubusercontent.com/MicrosoftSavvy/Released/refs/heads/main/NewITSoftware.txt").rawcontent).split("`n") | select-object -skip 26) -replace("`r",'')
	$SLCount=(($SoftwareList | Select-String -Pattern "Remove" -AllMatches).linenumber - 1)
	$Installs=($SoftwareList | Select -first $SLCount) | select -skip 1 | select -skiplast 1
	$Removals=($SoftwareList | Select -skip $SLCount) | select -skip 1 | select -skiplast 1
	UpdateModules
	Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
	foreach($Install in $Installs){
	$CurrentStatus = "Installing $Install" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	winget install $install --accept-source-agreements --accept-package-agreements --silent --disable-interactivity
	}
	foreach ($Removal in $Removals){
	$CurrentStatus = "Removing $Removal" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	$SoftwareRemove = (Get-AppxPackage | Where-Object { $_.Name -like $Removal }).PublisherId
	foreach($SR in $SoftwareRemove){
			if ($SR -like "MSIX*"){
				$SRX=$SR.replace("MSIX\","")
				Remove-AppXPackage -package $SRX
			}else{
	winget uninstall $SR
			}
		}	
	}
}

function SecurePC {
write-host $null | out-file $Folder\BitKeys-$CurrentDate.txt
foreach ($DriveLetter in $Drives){
	$drive=$DriveLetter.replace("\","")
	$Protectors=(manage-bde -protectors -get $drive).split()
	$LCount=($Protectors | Select-String -Pattern "ID:" -AllMatches).linenumber
	$IDs=$Protectors[$LCount]
	if (((manage-bde -protectors -get $drive | where-object { $_ -like "*TPM*" }) -eq $null)) {manage-bde -protectors -add -TPM $Drive}
	if (((manage-bde -protectors -get $drive | where-object { $_ -like "*Numerical*" }) -eq $null)) {manage-bde -protectors -add $Drive -RecoveryPassword}
	manage-bde -on $Drive -skiphardwaretest
	foreach ($ID in $IDs){
	if (((manage-bde -protectors -get $drive | where-object { $_ -like "*External*" }) -eq $null)) {manage-bde -protectors -add $Drive -RecoveryKey $Folder -id $ID}
	manage-bde -protectors -adbackup $Drive -id $ID
	manage-bde -protectors -aadbackup $Drive -id $ID
	$DocumentedKey=((Get-Content $Folder\BitKeys-$CurrentDate.txt | where-object { $_ -like "*$ID*" }))
	if ($DocumentedKey -eq $null){
	if (((manage-bde -protectors -get $drive -t recoverypassword).split() | where-object { $_ -like "ERROR:" }).length -lt 1) {
	(manage-bde -protectors -get $drive -t recoverypassword) | select -skip 3 | out-file $Folder\BitKeys-$CurrentDate.txt
	}
	}
	}
}
	$SCDownload="https://raw.githubusercontent.com/MicrosoftSavvy/Released/refs/heads/main/SecuritySettings.inf"
	$SCR=Invoke-WebRequest -uri $SCDownload
	$SCRaw=($SCR.rawcontent).split("`n") | Select-Object -skip 26
	$SetSecurityLog=$Folder + "\SetSecurityLog.log"
	$SetSecurity=$Folder + "\SetSecurity.inf"
	$SCRaw  | Out-File -FilePath $SetSecurity -force -encoding Unicode
	$content = Get-Content -Raw -Path $SetSecurity
	$updatedContent = $content -replace "`r`r`n", "`r`n"
	$SetSecurityLog=$Folder + "\SetSecurityLog.log"
	Set-Content -encoding Unicode -Path $SetSecurity -Value $updatedContent
	secedit /validate $SetSecurity
	secedit /generaterollback /cfg $SetSecurity /rbk $Folder\OriginalSecuritySettings.inf /quiet
	secedit /db secedit.sdb /import /cfg $SetSecurity /overwrite /log $SetSecurityLog /verbose /quiet
	secedit /db secedit.sdb /configure /cfg $SetSecurity /overwrite /log $SetSecurityLog /verbose /quiet
	BCDEDIT /set nx OptOut
	Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
	$PolicyCats="Account Management","Policy Change"
	$PolicySubs='logon','logoff','File System','File Share','Plug and Play Events','Credential Validation','Security Group Management','Process Creation','Special Logon','Other Object Access Events','System Integrity','Security State Change','Sensitive Privilege Use','Other Logon/Logoff Events','Other System Events','Security System Extension'
	$Policy=auditpol /set /category:* /failure:enable /success:disable
	foreach($PolicyCat in $PolicyCats){
		$Policy=auditpol /set /category:$PolicyCat /failure:enable /success:enable
	}
	foreach ($PolicySub in $PolicySubs){
		$Policy=auditpol /set /subcategory:$PolicySub /failure:enable /success:enable
	}
	auditpol /set /subcategory:"Security Group Management" /failure:disable /success:enable
	$DisableSubs="Filtering Platform Packet Drop"
	foreach ($DisableSub in $DisableSubs){
		$Policy=auditpol /set /subcategory:$DisableSub /failure:disable /success:disable
	}
	$Policy=auditpol /get /category:*
###Running manually if import log is empty
	if ((get-content $SetSecurityLog) -eq $null){
		if ((get-localuser).name -contains "Administrator") {Rename-LocalUser -Name Administrator -NewName LocalAdmin; disable-localuser LocalAdmin}
		if ((get-localuser).name -contains "Guest") {Rename-LocalUser -Name Guest -NewName LocalGuest; disable-localuser LocalGuest}
		net accounts /minpwage:1 /maxpwage:45 /lockoutthreshold:3 /lockoutduration:30 /lockoutwindow:15
		$NTRights=(get-childitem "c:\ntrights.exe" -recurse -erroraction silentlycontinue).fullname
		if ($NTRights.split().length -gt 1) {$NTRights=$NTRights[0]}
		if ($NTRights -eq $null) {
			$NTRightsLink="https://github.com/MicrosoftSavvy/Released/raw/refs/heads/main/ntrights.exe"
			Invoke-WebRequest $NTRightsLink -outfile $env:windir\ntrights.exe
			$NTRights=(get-childitem "c:\ntrights.exe" -recurse -erroraction silentlycontinue).fullname
			if ($NTRights.length -gt 1) {$NTRights=$NTRights[0]}
		}
		$UserGroups=(Get-LocalGroup).name
		$NTRCats=(&$ntrights | select -skip 8).Replace(" ","")
		$AdminService="Administrators","Local Service","Network Service","Service"
		$User="Administrators","Backup Operators","Power Users","Users"
		$BURights="Administrators","Backup Operators"
		$Admin="Administrators"
		$AdminRights='SeAuditPrivilege','SeSecurityPrivilege','SeCreateSymbolicLinkPrivilege','SeMachineAccountPrivilege','SeIncreaseQuotaPrivilege','SeSystemTimePrivilege','SeTimeZonePrivilege','SeTakeOwnershipPrivilege','SeEnableDelegationPrivilege','SeRemoteShutdownPrivilege','SeProfileSingleProcessPrivilege','SeLoadDriverPrivilege','SeDebugPrivilege','SeIncreaseBasePriorityPrivilege','SeSystemEnvironmentPrivilege','SeManageVolumePrivilege','SeSystemProfilePrivilege','SeUnsolicitedInputPrivilege'
		$BURights='SeBackupPrivilege','SeRestorePrivilege'
		$UserRights='SeShutdownPrivilege','SeCreatePagefilePrivilege','SeUndockPrivilege'
		$NoRights='SeCreatePermanentPrivilege','SeCreateTokenPrivilege','SeAssignPrimaryTokenPrivilege','SeTcbPrivilege,''SeLockMemoryPrivilege','SeChangeNotifyPrivilege','SeIncreaseWorkingSetPrivilege','SeRelabelPrivilege','SeDelegateSessionUserImpersonatePrivilege','SeSyncAgentPrivilege','SeTrustedCredManAccessPrivilege'
		$AdminServiceRights='SeImpersonatePrivilege','SeCreateGlobalPrivilege'
		$Users=(Get-LocalUser).name
		foreach($UserGroup in $UserGroups){
			foreach($NTRCat in $NTRCats){
			&$ntrights -r $NTRCat -u $UserGroup
			foreach($User in $Users){
			&$ntrights -r $NTRCat -u $User
			}
		if ($AdminRights -contains $NTRCat){
			foreach($CList in $Admin){
			&$ntrights +r $NTRCat -u $CList
			}
		}
		if ($BURights -contains $NTRCat){
			foreach($CList in $BU){
			&$ntrights +r $NTRCat -u $CList
			}
		}
		if ($UserRights -contains $NTRCat){
			foreach($CList in $User){
			&$ntrights +r $NTRCat -u $CList
			}
		}
		if ($AdminServiceRights -contains $NTRCat){
			foreach($CList in $AdminService){
			&$ntrights +r $NTRCat -u $CList
			}
		}
	Write-Output "Disabling AutoRun"	
	New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun -value 255 -type Dword -Force -ErrorAction 'SilentlyContinue'
	Write-Output "Enabling Edge SmartScreen Filter"
	$Key=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty 'EnableSmartScreen'
	if ($Key -eq $Null){
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Force -ErrorAction 'SilentlyContinue'
	}else {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Force -ErrorAction 'SilentlyContinue'
	}
	$Key=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty "ShellSmartScreenLevel" 
	if ($Key -eq $Null){
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value 1 -Force -ErrorAction 'SilentlyContinue'
	}else {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value 1 -Force -ErrorAction 'SilentlyContinue'
	}
	$Key=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty "EnabledV9"
	if ($Key -eq $Null){
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9"  -Value 1 -Force -ErrorAction 'SilentlyContinue'
	}else {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9"  -Value 1 -Force -ErrorAction 'SilentlyContinue'
	}
	$Key=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty "PreventOverride"
	if ($Key -eq $Null){
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverride"  -Value 1 -Force -ErrorAction 'SilentlyContinue'
	}else {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverride"  -Value 1 -Force -ErrorAction 'SilentlyContinue'
	}
	$Key=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty "PreventOverrideAppRepUnknown"
	if ($Key -eq $Null){
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverrideAppRepUnknown"  -Value 1 -Force -ErrorAction 'SilentlyContinue'
	}else {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverrideAppRepUnknown"  -Value 1 -Force -ErrorAction 'SilentlyContinue'
	}
	$Key=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -ErrorAction 'SilentlyContinue'
	if ($Key -eq $Null){
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic"  -Value 0 -Force -ErrorAction 'SilentlyContinue'
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest"  -Value 0 -Force -ErrorAction 'SilentlyContinue'
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic"  -Value 0 -Force -ErrorAction 'SilentlyContinue'
	}else {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic"  -Value 0 -Force -ErrorAction 'SilentlyContinue'
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest"  -Value 0 -Force -ErrorAction 'SilentlyContinue'
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic"  -Value 0 -Force -ErrorAction 'SilentlyContinue'
	}
	$Key=Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ErrorAction 'SilentlyContinue'
	if ($Key -eq $Null){
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic"  -Value 0 -Force -ErrorAction 'SilentlyContinue'
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs"  -Value 1 -Force -ErrorAction 'SilentlyContinue'
	New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic"  -Value 0 -Force -ErrorAction 'SilentlyContinue'
	}else {
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic"  -Value 0 -Force -ErrorAction 'SilentlyContinue'
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs"  -Value 1 -Force -ErrorAction 'SilentlyContinue'
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic"  -Value 0 -Force -ErrorAction 'SilentlyContinue'
	}
	Write-Output "Setting Smart Card Removal Behavior"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "scremoveoption" -Value 1 -Force -ErrorAction 'SilentlyContinue'
	Write-Output "Setting lock after 15 minutes of inactivity"
	powercfg.exe /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 900
	powercfg.exe /SETDCVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK 900
	$Key=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty 'InactivityTimeoutSecs'
	if ($Key -eq $Null){
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs'  -Value 0x00000384 -Force -ErrorAction 'SilentlyContinue'
	}else {
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs'  -Value 0x00000384 -Force -ErrorAction 'SilentlyContinue'
	}
	Write-Output "Enable NTLMv2 Only"
	Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -value 5 -Force -ErrorAction 'SilentlyContinue'
		}
	}
	}
##End Manual
	$Nics=(get-netipconfiguration).interfacealias	
	$netShare = New-Object -ComObject HNetCfg.HNetShare
	foreach($Nic in $Nics) {
		$interface=$nic
		$privateConnection = $netShare.EnumEveryConnection | Where-Object {$netShare.NetConnectionProps.Invoke($_).Name -eq $Interface}
		$privateConfig = $netShare.INetSharingConfigurationForINetConnection.Invoke($privateConnection)
		$privateConfig.DisableSharing()
		$privateConfig.EnableInternetFirewall()
	}	
}

function InteractiveAdmin {
	net localgroup administrators "NT AUTHORITY\INTERACTIVE" /add
}

function UpdateFeature {
	UpdateModules
	Install-WindowsUpdate -MicrosoftUpdate -Category 'feature pack','upgrades' -AcceptAll -Install -IgnoreReboot -Verbose
}

function UpdateDriver {
	UpdateModules
	Install-WindowsUpdate -MicrosoftUpdate -Category 'driver' -AcceptAll -Install -IgnoreReboot -Verbose
}

function OfficeReports {
	if ((get-installedmodule Microsoft.Graph).name -ne "Microsoft.Graph"){
	Install-Module Microsoft.Graph -Scope AllUsers -Repository PSGallery -Force
	}
	Microsoft.Graph.Authentication
	Connect-Graph -Scopes User.ReadWrite.All, Organization.Read.All, Directory.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All, DeviceManagementServiceConfig.Read.All
	$CBOffice.checked = $False
	$form.Controls.Add($CBOffice)

	if ($CBOLicense.checked -eq $True){
	$OfficeLicense=$Folder + "\LicensingInfo.log"
	Out-File -FilePath $OfficeLicense -InputObject (Get-MgSubscribedSku | format-table AccountName, ConsumedUnits, SkuPartNumber, SkuID)
	Get-MgSubscribedSku | out-gridview
	}
	
	if ($CBOLogins.checked -eq $True){
	$OfficeLogin=$Folder + "\OfficeLogins.log"
	Import-Module Microsoft.Graph.Reports
	Out-File -FilePath $OfficeLicense -InputObject (Get-MgAuditLogSignIn -Filter "Status/Errorcode ne 0" | Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, ClientAppUsed, ConditionalAccessStatus, ResourceDisplayName)
	Get-MgAuditLogSignIn | out-gridview
	}

	if ($CBOUnLicensedUsers.checked -eq $True){
	$CBOUnLicensed=$Folder + "\CBOUnLicensed.log"
	Import-Module Microsoft.Graph.Reports
	Out-File -FilePath $CBOUnLicensed -InputObject (Get-MgAuditLogSignIn -Filter "Status/Errorcode ne 0" | Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, ClientAppUsed, ConditionalAccessStatus, ResourceDisplayName)
	Get-MgAuditLogSignIn | out-gridview
	}


}


function ListSIDs {
	$SIDList=$Folder + "\SIDList.log"
[array]$SIDs = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" -ErrorAction SilentlyContinue |
ForEach-Object {
    $profilePath = $_.GetValue("ProfileImagePath")
    $sid = ($_.Name -replace "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\", "")
    if ($profilePath) { "$sid`t$profilePath" }
}	
	$SIDs | Out-File -file $SIDList -force -encoding utf8
	foreach ($SD in $SIDs){
	if ($Status -ne $null) {$Status.items.add($SD)}else {Write-Host $SD -foregroundcolor Green}
	}	
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
}

function GUI {
	[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
	[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null
	$FormColors=[Enum]::GetValues([System.Drawing.KnownColor]) | where {$_ -notlike "Menu*" -and $_ -notlike "Gradient*" -and $_ -notlike "Button*"-and $_ -notlike "Window*"-and $_ -notlike "Scroll*"-and $_ -notlike "Info*"-and $_ -notlike "Inactive*"-and $_ -notlike "Hot*"-and $_ -notlike "Highlight*"-and $_ -notmatch "Graytext"-and $_ -notlike "Control*"-and $_ -notmatch "AppWorkspace"-and $_ -notlike "Active*"-and $_ -notmatch "Desktop"-and $_ -notmatch "Transparent"}
	$form = New-Object System.Windows.Forms.Form
	$Run = New-Object System.Windows.Forms.Button
	$Repair = New-Object System.Windows.Forms.Button
	$Secure = New-Object System.Windows.Forms.Button
	$Clear = New-Object System.Windows.Forms.Button
	$Exit = New-Object System.Windows.Forms.Button
	$Update = New-Object System.Windows.Forms.Button
	$CBCleanUp = New-Object System.Windows.Forms.CheckBox
	$CBTime = New-Object System.Windows.Forms.CheckBox
	$CBSpaceCleanUp = New-Object System.Windows.Forms.CheckBox
	$CBNetwork = New-Object System.Windows.Forms.CheckBox
	$CBLogs = New-Object System.Windows.Forms.CheckBox
	$CBDLLs = New-Object System.Windows.Forms.CheckBox
	$CBBadDevices = New-Object System.Windows.Forms.CheckBox
	$CBCHK = New-Object System.Windows.Forms.CheckBox
	$CBDISM = New-Object System.Windows.Forms.CheckBox
	$CBSFC = New-Object System.Windows.Forms.CheckBox
	$CBRT = New-Object System.Windows.Forms.CheckBox
	$CBSR = New-Object System.Windows.Forms.CheckBox
	$CBST = New-Object System.Windows.Forms.CheckBox
	$CBSV = New-Object System.Windows.Forms.CheckBox
	$CBUpdate = New-Object System.Windows.Forms.CheckBox
	$CBNetwork = New-Object System.Windows.Forms.CheckBox
	$CBPCR = New-Object System.Windows.Forms.CheckBox
	$CBPCRST = New-Object System.Windows.Forms.CheckBox
	$CBVSS = New-Object System.Windows.Forms.CheckBox
	$CBSpool = New-Object System.Windows.Forms.CheckBox
	$CBDevices = New-Object System.Windows.Forms.CheckBox
	$CBEPO = New-Object System.Windows.Forms.CheckBox
	$CBServices = New-Object System.Windows.Forms.CheckBox
	$CBDS = New-Object System.Windows.Forms.CheckBox
	$CBNetCheck = New-Object System.Windows.Forms.CheckBox
	$CBRecycle = New-Object System.Windows.Forms.CheckBox
	$CBSecureHOSTS = New-Object System.Windows.Forms.CheckBox
	$CBSecurePC = New-Object System.Windows.Forms.CheckBox
	$CBIAdmin = New-Object System.Windows.Forms.CheckBox
	$CBWiFi = New-Object System.Windows.Forms.CheckBox
	$CBITPC = New-Object System.Windows.Forms.CheckBox
	$CBUF = New-Object System.Windows.Forms.CheckBox
	$CBUD = New-Object System.Windows.Forms.CheckBox
	$CBSIDs = New-Object System.Windows.Forms.CheckBox
	$CBOffice = New-Object System.Windows.Forms.CheckBox
	$CBOLogins = New-Object System.Windows.Forms.CheckBox
	$CBOLicense = New-Object System.Windows.Forms.CheckBox

	$TXTMIN = New-Object System.Windows.Forms.TextBox
	$Status = New-Object System.Windows.Forms.ListBox
	$TXTPCR = New-Object System.Windows.Forms.TextBox
	$DDDevices = New-Object System.Windows.Forms.ComboBox
	$ServiceList = New-Object System.Windows.Forms.ComboBox
	$tooltip1 = New-Object System.Windows.Forms.ToolTip
	$Run.Name="Run"
	$Repair.Name="Repair"
	$Secure.Name="Secure"
	$Clear.Name="Clear"
	$Exit.Name="Exit"
	$Update.Name="Update"
	$CBCleanUp.Name="CBCleanUp"
	$CBTime.Name="CBTime"
	$CBSpaceCleanUp.Name="CBSpaceCleanUp"
	$CBNetwork.Name="CBNetwork"
	$CBLogs.Name="CBLogs"
	$CBDLLs.Name="CBDLLs"
	$CBBadDevices.Name="CBBadDevices"
	$CBCHK.Name="CBCHK"
	$CBDISM.Name="CBDISM"
	$CBSFC.Name="CBSFC"
	$CBRT.Name="CBRT"
	$CBSR.Name="CBSR"
	$CBST.Name="CBST"
	$CBSV.Name="CBSV"
	$CBUpdate.Name="CBUpdate"
	$CBNetwork.Name="CBNetwork"
	$CBPCR.Name="CBPCR"
	$CBPCRST.Name="CBPCRST"
	$CBVSS.Name="CBVSS"
	$CBSpool.Name="CBSpool"
	$CBDevices.Name="CBDevices"
	$CBEPO.Name="CBEPO"
	$CBServices.Name="CBServices"
	$CBDS.Name="CBDS"
	$CBNetCheck.Name="CBNetCheck"
	$CBRecycle.Name="CBRecycle"
	$CBSecureHOSTS.Name="CBSecureHOSTS"
	$CBSecurePC.Name="CBSecurePC"
	$CBIAdmin.Name="CBIAdmin"
	$CBWiFi.Name="WiFi"
	$CBITPC.Name="CBITPC"
	$TXTMIN.Name="TXTMIN"
	$Status.Name="Status"
	$TXTPCR.Name="TXTPCR"
	$DDDevices.Name="DDDevices"
	$ServiceList.Name="ServiceList"
	$CBUF.Name="CBUF"
	$CBUD.Name="CBUD"
	$CBSIDs.Name="CBSIDs"
	$CBOffice.Name="CBOffice"
	$CBOLogins.Name="CBOLogins"
	$CBOLicense.Name="CBOLicense"
	$ShowHelp={
     Switch ($this.name) {
		"Run" {$tip = "Runs Checked options"}
		"Repair" {$tip = "Checks options that would be best for running repairs"}
		"Secure" {$tip = "Checks options that would be best to help secure PC"}
		"Clear" {$tip = "Clears all check boxes"}
		"Exit" {$tip = "Exit the Script"}
		"Update" {$tip = "Update the Script"}
		"CBCleanUp" {$tip = "Clean-up after running"}
		"CBTime" {$tip = "Check System Time to NTP"}
		"CBSpaceCleanUp" {$tip = "Free up space on PC"}
		"CBNetwork" {$tip = "Set network to private"}
		"CBLogs" {$tip = "Pull log files for time specified"}
		"CBDLLs" {$tip = "Re-Register all DLLs"}
		"CBBadDevices" {$tip = "Remove Devices with problematic drivers"}
		"CBCHK" {$tip = "Run CheckDisk"}
		"CBDISM" {$tip = "Run DISM and download source files if needed"}
		"CBSFC" {$tip = "Runs System File Checker"}
		"CBRT" {$tip = "Installs RunTimes"}
		"CBSR" {$tip = "Schedule restart if needed at 3AM"}
		"CBST" {$tip = "Pulls list of scheduled tasks that run as user or run at scheduled times"}
		"CBSV" {$tip = "Pulls varibles and exports them to a file"}
		"CBUpdate" {$tip = "Update the system"}
		"CBPCR" {$tip = "Rename PC to either Serial Number or custom setting"}
		"CBPCRST" {$tip = "Rename PC to Serial Number"}
		"CBVSS" {$tip = "Turn on Shadow Copies"}
		"CBSpool" {$tip = "Clear Print Spooler Folder"}
		"CBDevices" {$tip = "Remove all devices from the category selected"}
		"CBEPO" {$tip = "Enable all options in Power Settings"}
		"CBServices" {$tip = "Reset Permissions on service"}
		"CBDS" {$tip = "Download source files regards if needed"}
		"CBNetCheck" {$tip = "Checks DNS and if pingable"}
		"CBRecycle" {$tip = "Clear everyone's recycle bin"}
		"CBSecureHOSTS" {$tip = "Downloads a secure HOSTS file to assist in safer internet"}
		"CBSecurePC" {$tip = "Settings to assist in securing PC"}
		"CBIAdmin" {$tip = "Sets INTERACTIVE as admin giving all users admin rights to only this computer and only while signed in"}
		"TXTMIN" {$tip = "Time to go back for logs"}
		"Status" {$tip = "Current status window"}
		"TXTPCR" {$tip = "Rename PC to ..."}
		"DDDevices" {$tip = "Remove all devices of this type"}
		"ServiceList" {$tip = "List of services"}
		"WiFi" {$tip = "List all saved wifi passwords"}
		"CBITPC" {$tip = "Removes McAfee and Norton, Installs PDQ, Putty, IP Scanner"}
        "CBUF" {$tip = "Run Windows Updates from Feature Pack category only"}
		"CBUD" {$tip = "Run Windows Updates from Driver category only"}
		"CBSIDs" {$tip = "List local SIDs"}
		"CBOffice" {$tip = "List local SIDs"}
		"CBOLogins" {$tip = "List local SIDs"}
		"CBOLicense" {$tip = "List local SIDs"}

	  }
$tooltip1.SetToolTip($this,$tip)
}
$Run.add_MouseHover($ShowHelp)
$Repair.add_MouseHover($ShowHelp)
$Secure.add_MouseHover($ShowHelp)
$Clear.add_MouseHover($ShowHelp)
$Exit.add_MouseHover($ShowHelp)
$Update.add_MouseHover($ShowHelp)
$CBCleanUp.add_MouseHover($ShowHelp)
$CBTime.add_MouseHover($ShowHelp)
$CBSpaceCleanUp.add_MouseHover($ShowHelp)
$CBNetwork.add_MouseHover($ShowHelp)
$CBLogs.add_MouseHover($ShowHelp)
$CBDLLs.add_MouseHover($ShowHelp)
$CBBadDevices.add_MouseHover($ShowHelp)
$CBCHK.add_MouseHover($ShowHelp)
$CBDISM.add_MouseHover($ShowHelp)
$CBSFC.add_MouseHover($ShowHelp)
$CBRT.add_MouseHover($ShowHelp)
$CBSR.add_MouseHover($ShowHelp)
$CBST.add_MouseHover($ShowHelp)
$CBSV.add_MouseHover($ShowHelp)
$CBUpdate.add_MouseHover($ShowHelp)
$CBNetwork.add_MouseHover($ShowHelp)
$CBTime.add_MouseHover($ShowHelp)
$CBCleanUp.add_MouseHover($ShowHelp)
$CBPCR.add_MouseHover($ShowHelp)
$CBPCRST.add_MouseHover($ShowHelp)
$CBVSS.add_MouseHover($ShowHelp)
$CBSpool.add_MouseHover($ShowHelp)
$CBDevices.add_MouseHover($ShowHelp)
$CBEPO.add_MouseHover($ShowHelp)
$CBServices.add_MouseHover($ShowHelp)
$CBDS.add_MouseHover($ShowHelp)
$CBNetCheck.add_MouseHover($ShowHelp)
$CBRecycle.add_MouseHover($ShowHelp)
$CBSecureHOSTS.add_MouseHover($ShowHelp)
$CBSecurePC.add_MouseHover($ShowHelp)
$CBIAdmin.add_MouseHover($ShowHelp)
$CBWiFi.add_MouseHover($ShowHelp)
$TXTMIN.add_MouseHover($ShowHelp)
$Status.add_MouseHover($ShowHelp)
$TXTPCR.add_MouseHover($ShowHelp)
$DDDevices.add_MouseHover($ShowHelp)
$ServiceList.add_MouseHover($ShowHelp)
$CBITPC.add_MouseHover($ShowHelp)
$CBUF.add_MouseHover($ShowHelp)
$CBUD.add_MouseHover($ShowHelp)
$CBSIDs.add_MouseHover($ShowHelp)
$CBOffice.add_MouseHover($ShowHelp)
$CBOLogins.add_MouseHover($ShowHelp)
$CBOLicense.add_MouseHover($ShowHelp)

	$form.Text = "The Little Helper GUI $CurrentScriptVer"
	$form.Autosize = $True
	if ( -not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
		$CurrentStatus = "Need to run with Administrator Rights" 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	} 
	
	$CBCleanUp.Text = "Clean Up"
	$CBCleanUp.Location = New-Object System.Drawing.Point(10, 10)
	$CBCleanUp.Autosize = $True
	$CBCleanUp.checked = $False
	$form.Controls.Add($CBCleanUp)
	
	$CBTime.Name="CBTime"
	$CBTime.Text = "Fix Time"
	$CBTime.Location = New-Object System.Drawing.Point(10, 30)
	$CBTime.Autosize = $True
	$CBTime.checked = $False
	$form.Controls.Add($CBTime)
	
	$CBSpaceCleanUp.Text = "Space Clean-Up"
	$CBSpaceCleanUp.Location = New-Object System.Drawing.Point(10, 50)
	$CBSpaceCleanUp.Autosize = $True
	$CBSpaceCleanUp.checked = $False
	$form.Controls.Add($CBSpaceCleanUp)
	
	$CBNetwork.Text = "Set Network as Private"
	$CBNetwork.Location = New-Object System.Drawing.Point(10, 70)
	$CBNetwork.Autosize = $True
	$CBNetwork.checked = $False
	$form.Controls.Add($CBNetwork)

	$CBLogs.Text = "Pull Logs (min)"
	$CBLogs.Location = New-Object System.Drawing.Point(10, 90)
	$CBLogs.Autosize = $True
	$CBLogs.checked = $False
	$form.Controls.Add($CBLogs)

	$CBDLLs.Text = "Re-Register DLLs"
	$CBDLLs.Location = New-Object System.Drawing.Point(10, 110)
	$CBDLLs.Autosize = $True
	$CBDLLs.checked = $False
	$form.Controls.Add($CBDLLs)

	$CBDISM.Text = "Run DISM"
	$CBDISM.Location = New-Object System.Drawing.Point(10, 130)
	$CBDISM.Autosize = $True
	$CBDISM.checked = $False
	$form.Controls.Add($CBDISM)

	$CBVSS.Text = "Turn On VSS"
	$CBVSS.Location = New-Object System.Drawing.Point(10, 150)
	$CBVSS.Autosize = $True
	$CBVSS.checked = $False
	$form.Controls.Add($CBVSS)

	$CBPCR.Text = "Rename PC"
	$CBPCR.Location = New-Object System.Drawing.Point(10, 190)
	$CBPCR.Autosize = $True
	$CBPCR.checked = $False
	$form.Controls.Add($CBPCR)

	$CBBadDevices.Text = "Remove Problematic Devices"
	$CBBadDevices.Location = New-Object System.Drawing.Point(160, 10)
	$CBBadDevices.Autosize = $True
	$CBBadDevices.checked = $False
	$form.Controls.Add($CBBadDevices)

	$CBSFC.Text = "Run System File Checker"
	$CBSFC.Location = New-Object System.Drawing.Point(160, 30)
	$CBSFC.Autosize = $True
	$CBSFC.checked = $False
	$form.Controls.Add($CBSFC)

	$CBRT.Text = "Install Runtimes"
	$CBRT.Location = New-Object System.Drawing.Point(160, 50)
	$CBRT.Autosize = $True
	$CBRT.checked = $False
	$form.Controls.Add($CBRT)
	
	$CBSR.Text = "Schedule Restart"
	$CBSR.Location = New-Object System.Drawing.Point(160, 70)
	$CBSR.Autosize = $True
	$CBSR.checked = $False
	$form.Controls.Add($CBSR)

	$CBST.Text = "Export Scheduled Tasks"
	$CBST.Location = New-Object System.Drawing.Point(160, 90)
	$CBST.Autosize = $True
	$CBST.checked = $False
	$form.Controls.Add($CBST)

	$CBSV.Text = "Export Varibles"
	$CBSV.Location = New-Object System.Drawing.Point(160, 110)
	$CBSV.Autosize = $True
	$CBSV.checked = $False
	$form.Controls.Add($CBSV)

	$CBCHK.Text = "Run Check Disk"
	$CBCHK.Location = New-Object System.Drawing.Point(160, 130)
	$CBCHK.Autosize = $True
	$CBCHK.checked = $False
	$form.Controls.Add($CBCHK)

	$CBSpool.Text = "Clear Spooler"
	$CBSpool.Location = New-Object System.Drawing.Point(160, 150)
	$CBSpool.Autosize = $True
	$CBSpool.checked = $False
	$form.Controls.Add($CBSpool)

	$CBPCRST.Text = "SN"
	$CBPCRST.Location = New-Object System.Drawing.Point(100, 190)
	$CBPCRST.Autosize = $True
	$CBPCRST.checked = $False
	$form.Controls.Add($CBPCRST)	
	$CBPCRST.Enabled=$False

	$CBEPO.Text = "Enable All Power Options"
	$CBEPO.Location = New-Object System.Drawing.Point(10, 170)
	$CBEPO.Autosize = $True
	$CBEPO.checked = $False
	$form.Controls.Add($CBEPO)

	$CBDevices.Text = "Remove All Devices Of"
	$CBDevices.Location = New-Object System.Drawing.Point(10, 210)
	$CBDevices.Autosize = $True
	$CBDevices.checked = $False
	$form.Controls.Add($CBDevices)	

	$CBDS.Text = "Download Source Files"
	$CBDS.Location = New-Object System.Drawing.Point(340, 10)
	$CBDS.Autosize = $True
	$CBDS.checked = $False
	$form.Controls.Add($CBDS)

	$CBNetCheck.Text = "Run Network Check"
	$CBNetCheck.Location = New-Object System.Drawing.Point(160, 170)
	$CBNetCheck.Autosize = $True
	$CBNetCheck.checked = $False
	$form.Controls.Add($CBNetCheck)	
	
	@((gwmi win32_PnPSignedDriver).deviceclass | sort-object -unique) | ForEach-Object {[void] $DDDevices.Items.Add($_)}
	$DDDevices.width=170
	$DDDevices.autosize = $true
	$DDDevices.location = New-Object System.Drawing.Point(160,210)
	$DDDevices.Enabled=$False
	$form.Controls.Add($DDDevices)

	$CBServices.Text = "Reset Owner of Service"
	$CBServices.Location = New-Object System.Drawing.Point(10, 230)
	$CBServices.Autosize = $True
	$CBServices.checked = $False
	$form.Controls.Add($CBServices)	
	
	$CBRecycle.Text = "Clear All Recycle Bins"
	$CBRecycle.Location = New-Object System.Drawing.Point(340, 30)
	$CBRecycle.Autosize = $True
	$CBRecycle.checked = $False
	$form.Controls.Add($CBRecycle)	

	$CBSecureHOSTS.Text = "Secure HOSTS file"
	$CBSecureHOSTS.Location = New-Object System.Drawing.Point(340, 50)
	$CBSecureHOSTS.Autosize = $True
	$CBSecureHOSTS.checked = $False
	$form.Controls.Add($CBSecureHOSTS)	

	$CBSecurePC.Text = "Secure PC"
	$CBSecurePC.Location = New-Object System.Drawing.Point(340, 70)
	$CBSecurePC.Autosize = $True
	$CBSecurePC.checked = $False
	$form.Controls.Add($CBSecurePC)

	$CBIAdmin.Text = "Make INTERACTIVE Admin"
	$CBIAdmin.Location = New-Object System.Drawing.Point(340, 90)
	$CBIAdmin.Autosize = $True
	$CBIAdmin.checked = $False
	$form.Controls.Add($CBIAdmin)
		
	$CBWiFi.Text = "Pull Wi-Fi Passwords"
	$CBWiFi.Location = New-Object System.Drawing.Point(340, 110)
	$CBWiFi.Autosize = $True
	$CBWiFi.checked = $False
	$form.Controls.Add($CBWiFi)
	
	$CBITPC.Text = "New Tech PC"
	$CBITPC.Location = New-Object System.Drawing.Point(340, 130)
	$CBITPC.Autosize = $True
	$CBITPC.checked = $False
	$form.Controls.Add($CBITPC)
	
	$CBUpdate.Text = "Update PC"
	$CBUpdate.Location = New-Object System.Drawing.Point(340, 150)
	$CBUpdate.Autosize = $True
	$CBUpdate.checked = $False
	$form.Controls.Add($CBUpdate)
	
	$CBUF.Text = "Update Feature Pack"
	$CBUF.Location = New-Object System.Drawing.Point(340, 170)
	$CBUF.Autosize = $True
	$CBUF.checked = $False
	$form.Controls.Add($CBUF)
	
	$CBUD.Text = "Update Drivers"
	$CBUD.Location = New-Object System.Drawing.Point(340, 190)
	$CBUD.Autosize = $True
	$CBUD.checked = $False
	$form.Controls.Add($CBUD)
		
	$CBSIDs.Text = "Pull SIDs"
	$CBSIDs.Location = New-Object System.Drawing.Point(340, 210)
	$CBSIDs.Autosize = $True
	$CBSIDs.checked = $False
	$form.Controls.Add($CBSIDs)
	
	$CBOffice.Text = "Office 365 Reports"
	$CBOffice.Location = New-Object System.Drawing.Point(340, 230)
	$CBOffice.Autosize = $True
	$CBOffice.checked = $False
	$form.Controls.Add($CBOffice)

	$CBOLogins.Text = "Pull Office 365 Logins"
	$CBOLogins.Location = New-Object System.Drawing.Point(490, 10)
	$CBOLogins.Autosize = $True
	$CBOLogins.checked = $False

	$CBOLicense.Text = "Pull Licenses"
	$CBOLicense.Location = New-Object System.Drawing.Point(490, 30)
	$CBOLicense.Autosize = $True
	$CBOLicense.checked = $False
	
	
	$CBOUnLicensedUsers.Text = "List of Unlicensed Users"
	$CBOUnLicensedUsers.Location = New-Object System.Drawing.Point(490, 30)
	$CBOUnLicensedUsers.Autosize = $True
	$CBOUnLicensedUsers.checked = $False
	
	
	@((get-service).name) | ForEach-Object {[void] $ServiceList.Items.Add($_)}
	$ServiceList.width=170
	$ServiceList.autosize = $true
	$ServiceList.location = New-Object System.Drawing.Point(160,230)
	$ServiceList.Enabled=$False
	$form.Controls.Add($ServiceList)

	$TXTPCR.Location = New-Object System.Drawing.Point(160,190)
	$TXTPCR.Size = New-Object System.Drawing.Size(170,20)
	$TXTPCR.Multiline = $false
	$TXTPCR.AcceptsReturn = $false
	$form.Controls.Add($TXTPCR)        
	$TXTPCR.Enabled=$False

	$CBPCR.Add_CheckedChanged({
    if ($CBPCR.Checked) {
	$CBPCRST.Enabled=$True
	$TXTPCR.Enabled=$True
    } else {
	$CBPCRST.Enabled=$False
	$TXTPCR.Enabled=$False
	}
	})

	$TXTMIN.Location = New-Object System.Drawing.Point(110,90)
	$TXTMIN.Size = New-Object System.Drawing.Size(30,20)
	$TXTMIN.Multiline = $false
	$TXTMIN.AcceptsReturn = $false
	$form.Controls.Add($TXTMIN)        
	$TXTMIN.Text=180
	$TXTMIN.Enabled=$False

	$CBLogs.Add_CheckedChanged({
    if ($CBLogs.Checked) {
	$TXTMIN.Enabled=$True
    } else {
	$TXTMIN.Enabled=$False
	}
	})
	
	$CBOffice.Add_CheckedChanged({
    if ($CBOffice.Checked) {
	$form.Controls.Add($CBOLogins)
	$form.Controls.Add($CBOLicense)
	$form.Controls.Add($CBOUnLicensedUsers)
	$form.Autosize = $True	
   	} else {
	$form.Autosize = $False
	$form.Controls.Remove($CBOLogins)
	$form.Controls.Remove($CBOLicense)
	$form.Controls.Remove($CBOUnLicensedUsers)
	$form.Autosize = $True
	}
	})




	
	$CBServices.Add_CheckedChanged({
    if ($CBServices.Checked) {
	$ServiceList.Enabled=$True
    } else {
	$ServiceList.Enabled=$False
	}
	})

	$CBPCRST.Add_CheckedChanged({
    if ($CBPCRST.Checked) {
	$TXTPCR.Enabled=$False
    } else {
	$TXTPCR.Enabled=$True
	}
})

	$CBDevices.Add_CheckedChanged({
    if ($CBDevices.Checked) {
	$DDDevices.Enabled=$True
    } else {
	$DDDevices.Enabled=$False
	}
})

	$Clear.Text = "Clear"
	$Clear.Location = New-Object System.Drawing.Point(250, 255)
	$Clear.Add_Click({
	($CBNetwork.Checked) = $false
	($CBLogs.Checked) = $false
	($CBDLLs.Checked) = $false
	($CBBadDevices.Checked) = $false
	($CBCHK.Checked) = $false
	($CBDISM.Checked) = $false
	($CBSFC.Checked) = $false
	($CBRT.Checked) = $false
	($CBSR.Checked) = $false
	($CBST.Checked) = $false
	($CBSV.Checked) = $false
	($CBUpdate.Checked) = $false
	($CBCleanUp.Checked) = $false
	($CBTime.Checked) = $false
	($CBSpaceCleanUp.Checked) = $false
	($CBPCR.Checked) = $false
	($CBVSS.Checked) = $false
	($CBSpool.checked) = $false
	($CBDevices.Checked) = $false
	($CBEPO.Checked) = $false
	($CBServices.checked) = $false
	($CBDS.checked) = $false
	($CBNetCheck.checked) = $false
	($CBRecycle.checked) = $False
	($CBSecureHOSTS.checked) = $False
	($CBSecurePC.checked) = $False
	($CBIAdmin.checked) = $False
	($CBWiFi.checked) = $False
	($CBITPC.checked) = $False
	($CBUF.checked) = $False
	($CBUD.checked) = $False
	($CBSIDs.checked) = $False
	($CBOffice.checked) = $False
	$form.BackColor = [System.Drawing.Color]::LightGray
	})

	$Secure.Text = "Secure PC"
	$Secure.Location = New-Object System.Drawing.Point(90, 255)
	$Secure.Add_Click({
	($CBNetwork.Checked) = $false
	($CBLogs.Checked) = $false
	($CBDLLs.Checked) = $false
	($CBBadDevices.Checked) = $false
	($CBCHK.Checked) = $false
	($CBDISM.Checked) = $false
	($CBSFC.Checked) = $false
	($CBRT.Checked) = $false
	($CBSR.Checked) = $false
	($CBST.Checked) = $true
	($CBSV.Checked) = $false
	($CBUpdate.Checked) = $true
	($CBCleanUp.Checked) = $false
	($CBTime.Checked) = $true
	($CBSpaceCleanUp.Checked) = $false
	($CBPCR.Checked) = $false
	($CBVSS.Checked) = $true
	($CBSpool.checked) = $false
	($CBDevices.Checked) = $false
	($CBEPO.Checked) = $true
	($CBServices.checked) = $false
	($CBDS.checked) = $false
	($CBNetCheck.checked) = $true
	($CBRecycle.checked) = $False
	($CBSecureHOSTS.checked) = $True
	($CBSecurePC.checked) = $True
	($CBIAdmin.checked) = $False
	($CBWiFi.checked) = $False
	($CBITPC.checked) = $False
	($CBUF.checked) = $True
	($CBUD.checked) = $False
	($CBSIDs.checked) = $False
	($CBOffice.checked) = $False
	})
	
	$Repair.Text = "Repair OS"
	$Repair.Location = New-Object System.Drawing.Point(170, 255)
	$Repair.Add_Click({
	($CBNetwork.Checked) = $true
	($CBLogs.Checked) = $true
	($CBDLLs.Checked) = $true
	($CBBadDevices.Checked) = $true
	($CBCHK.Checked) = $true
	($CBDISM.Checked) = $true
	($CBSFC.Checked) = $true
	($CBRT.Checked) = $false
	($CBSR.Checked) = $false
	($CBST.Checked) = $false
	($CBSV.Checked) = $false
	($CBUpdate.Checked) = $false
	($CBCleanUp.Checked) = $false
	($CBTime.Checked) = $true
	($CBSpaceCleanUp.Checked) = $false
	($CBPCR.Checked) = $false
	($CBVSS.Checked) = $true
	($CBSpool.checked) = $false
	($CBDevices.Checked) = $false
	($CBEPO.Checked) = $false
	($CBServices.checked) = $false
	($CBDS.checked) = $false
	($CBNetCheck.checked) = $false
	($CBRecycle.checked) = $False
	($CBSecureHOSTS.checked) = $false
	($CBSecurePC.checked) = $false
	($CBIAdmin.checked) = $False
	($CBWiFi.checked) = $False
	($CBITPC.checked) = $False
	($CBUF.checked) = $False
	($CBUD.checked) = $False
	($CBSIDs.checked) = $False
	($CBOffice.checked) = $False
	})

	$Update.Text = "Update"
	$Update.Location = New-Object System.Drawing.Point(330, 255)
	$Update.Add_Click({
    	AppUpdate
	})

	$Exit.Text = "Exit"
	$Exit.Location = New-Object System.Drawing.Point(410, 255)
	$Exit.Add_Click({
		$form.Dispose()
    	$form.Close()
	})

	$Run.Text = "Run"
	$Run.Location = New-Object System.Drawing.Point(10, 255)
	$Run.Add_Click({
	if ($CBNetwork.Checked) { PrivateNetwork }
	if ($CBDLLs.Checked) { ReRegDLLs }
	if ($CBBadDevices.Checked) { RemoveBadDevices }
	if ($CBCHK.Checked) { RunCHK }
	if ($CBDISM.Checked) { RunDISM; if(!$DismRestoreResults.imagehealthstate -like 'Healthy'){DownloadSource; ConvertSource; DISMRepairSource} }
	if ($CBSFC.Checked) { RunSFC }
	if ($CBRT.Checked) { Runtimes }
	if ($CBST.Checked) { ScheduledTasks }
	if ($CBSV.Checked) { ShowVaribles }
	if ($CBUpdate.Checked) { Update }
	if ($CBTime.Checked) { FixTime }
	if ($CBSR.Checked) { ScheduleRestart }
	if ($CBPCR.Checked) { PC-Rename }
	if ($CBVSS.Checked) { VSS }
	if ($CBSpool.Checked) { Spooler }
	if ($CBDevices.Checked) { RemoveDeviceGroup }
	if ($CBEPO.Checked) { EnablePowerOptions }
	if ($CBServices.checked) { ServiceOwner }
	if ($CBSpaceCleanUp.Checked) { FreeUpSpace }
	if ($CBLogs.Checked) { Pull-Logs }
	if ($CBCleanUp.Checked) { CleanUp }
	if ($CBDS.checked) { DownloadSource }
	if ($CBNetCheck.checked) { NetworkCheck }
	if ($CBRecycle.checked) { ClearBins }
	if ($CBSecureHOSTS.checked) { SecureHost }
	if ($CBSecurePC.checked) { SecurePC }
	if ($CBIAdmin.checked) { InteractiveAdmin }
	if ($CBWiFi.checked) { PullWiFiPWDs }
	if ($CBITPC.checked) { NewITPC }
	if ($CBUF.checked) { UpdateFeature }
	if ($CBUD.checked) { UpdateDriver }
	if ($CBSIDs.checked) { ListSIDs }
	if ($CBOffice.checked) { OfficeReports }
	$Status.items.add("--------------")
	$Status.items.add("Run Finished")
	$StatusLog=$Folder + "\RunStatus.log"
	if (Test-Path [System.Windows.Forms.Application]) {[System.Windows.Forms.Application]::DoEvents()}
	Out-File -FilePath $StatusLog -InputObject ($Status.items)

	$Rand=Get-Random -Maximum $FormColors.length
	$Fcolor=$FormColors[$Rand]
	$form.BackColor = [System.Drawing.Color]::$FColor 
	})

	$form.Controls.Add($Run)
	$form.Controls.Add($Repair)
	$form.Controls.Add($Secure)
	$form.Controls.Add($Clear)
	$form.Controls.Add($Update)
	$form.Controls.Add($Exit)

	$Status.items.add("Form color will change once complete")
	if ($DownloadScriptVer -gt $CurrentScriptVer){
		$CurrentStatus = "Update Available" 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	}

	$Status.Location = New-Object System.Drawing.Point(10, 290)
	$Status.Size = New-Object System.Drawing.Size(495, 100)
	$form.Controls.Add($Status)
	[void]$form.ShowDialog()
}

clear-host
start-transcript -path $Transcript -append
GUI #
#Run-Repairs
Stop-Transcript

#Written by MicrosoftSavvy
#powershell -executionpolicy bypass -c $Link='https://raw.githubusercontent.com/MicrosoftSavvy/Released/refs/heads/main/LittleTechHelper.ps1'; $FileScript=$env:temp + '\temp.ps1'; invoke-webrequest $Link -outfile $FileScript; powershell -executionpolicy bypass -file $FileScript
