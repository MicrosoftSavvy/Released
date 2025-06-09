Set-ExecutionPolicy -executionpolicy bypass -scope Process -force
$CurrentScriptVer="1.0.8"
$host.UI.RawUI.WindowTitle = "The Little Helper Script $CurrentScriptVer"

$Folder='c:\Repair'
$MinutesBack=180
$Time="03:00"
$Date=(Get-date).AddDays(1).ToString('MM-dd-yyyy')
$CBSLog=$Folder + "\CBSLog.log"
$DISMLog=$Folder + "\DISMLog.log"
$VaribleExport=$Folder + "\Varibles.log"
$DLLRLog=$Folder + "\DLLReRegister.log"
$Transcript=$Folder + "\Transcript.log"
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
$DLLFolders='c:\Windows\System32','c:\Windows\Syswow64'
$DownLoad=($FindFile.links | Where-Object {$_.outertext -like "$OSType*"}).outerhtml
$DLF=$DownLoad.replace('<A href=','')
$DLF=$DLF -replace '"',' '
$File2Download=$DLF.Split()[1]
$FN=$DLF.Split()[2]
$FileName=$FN.substring(1)
$File2Download=$File2Download.replace('amp;','')
$File=$Folder+'\'+$FileName
$RestartSchedule=(schtasks /Create /SC ONCE /TN "ScheduledRestart" /TR "shutdown /r /f /t 0" /SD $Date /ST $time /F /Z /rl HIGHEST /ru System /V1)
$Global:DLLLog
$Global:NetRuntime
$NRTLog=$Folder+"\Runtime.log"
$WinGetLog=$Folder+"\AppUpdate.log"
#$RTLinks='https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170'
$Runtimes='https://aka.ms/vs/17/release/vc_redist.x86.exe','https://aka.ms/vs/17/release/vc_redist.x64.exe','https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe','https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe'
$SystemLog=$Folder+"\System.log"
$ApplicationLog=$Folder+"\Application.log"
$SecurityLog=$Folder+"\Security.log"
$StartLogDate=(Get-date).addminutes(-$MinutesBack).tostring('yyyy-MM-dd HH:mm:ss')
$CurrentDate=(Get-date).tostring('yyyy-MM-dd HH:mm:ss')
$hardwaretype=(Get-WmiObject -Class Win32_ComputerSystem -Property PCSystemType).PCSystemType
$Users= get-childitem -directory -path "c:\users"; 
$FUSFolders=@('c:\ESD','C:\Windows\SoftwareDistribution\Download','c:\ProgramData\Adobe\Temp','c:\$GetCurrent','c:\recovery','c:\windows10upgrade','C:\WINDOWS\SystemTemp\ScreenConnect') 
$Global:UserScheduledTasks
$USTLog=$Folder+"\ScheduledTasks-User.log"
$Global:TimeScheduledTasks
$NetworkLog=$Folder+"\Network.log"
$TSTLog=$Folder+"\ScheduledTasks-Timed.log"
$Network=(Get-NetConnectionProfile).Name
$FormColors="Yellow","Blue","Red","Green","LightBlue", "DarkRed","LightGreen"
$RunAfter=$Folder+"\Repair.ps1"
$VSSLog=$Folder+"\VSS.log"
$Global:VSSChangeLog 
$Spool="C:\Windows\System32\Spool"
$Spooler="C:\Windows\System32\Spool\Printers"
$Script=invoke-webrequest -uri https://raw.githubusercontent.com/MicrosoftSavvy/Released/refs/heads/main/FullScript.ps1
#$DownloadScriptVer=(((($Script.rawcontent).split("`n") | Select-Object -skip 29) | Select-Object -first 1) -Replace '[^0-9.]','')
$ScriptRaw=(($Script.rawcontent).split("`n")).replace("`r",'') | Select-Object -skip 26
$DownloadScriptVer=($ScriptRaw | Where-Object { $_ -match "$CurrentScriptVer" }) -replace "[^\d.]",""

if(!(test-path $Folder)){New-Item -Path $Folder -ItemType "directory"}

function PendingReboot {
	$CurrentStatus = "Checking if a reboot is pending" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()
	if (Get-ChildItem 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -EA Ignore) { return $true }
	if (Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -EA Ignore) { return $true }
	if (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -EA Ignore) { return $true }
	try {$util = [wmiclass]'\\.\root\ccm\clientsdk:CCM_ClientUtilities'
	$status = $util.DetermineIfRebootPending() 
	if (($status -ne $null) -and $status.RebootPending) {return $true; $Status.items.add("Restart is pending")}} catch { }; return $false
} 

function Pull-Logs {
	$CurrentStatus = "Pulling errors from log files" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()
	$System = (Get-EventLog -LogName System -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "Error" | Format-Table -AutoSize -Wrap)
	$Application = (Get-EventLog -LogName Application -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "Error" | Format-Table -AutoSize -Wrap)
	$Security = (Get-EventLog -LogName Security -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "FailureAudit" | Format-Table -AutoSize -Wrap)
	$DISMContents=get-content "c:\Windows\Logs\DISM\DISM.log"  | Where-Object { $_ -GE $StartLogDate} 
	$DISMErr=$DISMContents | Select-String 'Err'
	$DISMErrors=$DISMContents | Select-String -SimpleMatch 'ERROR'
	if(!$DISMErrors -eq $null){Out-File -FilePath $DISMLog -InputObject $DISMErr.line} else {Out-File -FilePath $DISMLog -InputObject $DISMErrors.line}
	$CBSContents=get-content "c:\Windows\Logs\CBS\CBS.log"  | Where-Object { $_ -GE $StartLogDate} 
	$CBSErr=$CBSContents | Select-String 'Err'
	$CBSErrors=$CBSContents | Select-String -SimpleMatch 'ERROR'
	if(!$CBSErrors -eq $null){Out-File -FilePath $CBSLog -InputObject $CBSErr.line} else {Out-File -FilePath $CBSLog -InputObject $CBSErrors.line}
	if (!($Global:DLLLog -eq $null)){Out-File -FilePath $DLLRLog -InputObject $Global:DLLLog}
	if (!($Global:WinGet -eq $null)){Out-File -FilePath $WinGetLog -InputObject $Global:WinGet}
	if (!($Global:NetRuntime -eq $null)){Out-File -FilePath $NRTLog -InputObject $Global:NetRuntime}
	if (!($System -eq $null)){Out-File -FilePath $SystemLog -InputObject (Get-EventLog -LogName System -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "Error" | Format-Table -AutoSize -Wrap)}
	if (!($Application -eq $null)){Out-File -FilePath $ApplicationLog -InputObject (Get-EventLog -LogName Application -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "Error" | Format-Table -AutoSize -Wrap)}
	if (!($Security -eq $null)){Out-File -FilePath $SecurityLog -InputObject (Get-EventLog -LogName Security -After (Get-Date).AddMinutes(-$MinutesBack) -entrytype "FailureAudit" | Format-Table -AutoSize -Wrap)}
	if (!($Global:UserScheduledTasks -eq $null)){Out-File -FilePath $USTLog -InputObject $Global:UserScheduledTasks}
	if (!($Global:TimeScheduledTasks -eq $null)){Out-File -FilePath $TSTLog -InputObject $Global:TimeScheduledTasks}
	if (!($Network -eq $null)){Out-File -FilePath $NetworkLog -InputObject $Network}
	if (!($Global:NetworkOld -eq $null)){Out-File -FilePath $NetworkLog -InputObject $Global:NetworkOld -append}
	if (!($Global:NetworkNew -eq $null)){Out-File -FilePath $NetworkLog -InputObject $Global:NetworkNew -append}
	if (!($Global:VSSChangeLog -eq $null)){Out-File -FilePath $VSSLog -InputObject $Global:VSSChangeLog}
}

function VSS {
	if (!(Get-ScheduledTask | Where-Object { $_.TaskName -like '*Shadow*' } | Select-Object TaskName, State)){
		$driveLetter = "C:\"
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
		-Argument "-command ""(Get-WmiObject -List Win32_ShadowCopy).Create(`"$driveLetter`", `"ClientAccessible`")"""
		$trigger1 = New-ScheduledTaskTrigger -Daily -At 7AM
		$trigger2 = New-ScheduledTaskTrigger -Daily -At 12PM
		$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries 
		Register-ScheduledTask -Action $action -Trigger $trigger1, $trigger2 -Settings $settings `
		-TaskName "ShadowCopyCreation" `
		-Description "Task for creating Shadow Copies"
		$Global:VSSChangeLog = $Global:VSSChangeLog + "Scheduled Task for creating Shadow Copies at 7AM and 12PM for drive $driveLetter is set."
		if ($Status -ne $null) {$Status.items.add($Global:VSSChangeLog)}else {Write-Host $Global:VSSChangeLog -foregroundcolor Green}
		[System.Windows.Forms.Application]::DoEvents()
	
} else {$Global:VSSChangeLog = "VSS Already Enabled.`n"; if ($Status -ne $null) {$Status.items.add($Global:VSSChangeLog)}else {Write-Host $Global:VSSChangeLog -foregroundcolor Green}
}
}

function RunDISM {
	$CurrentStatus = "Checking System Files" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()
	$DismScanResults=(Repair-WindowsImage -Online -scanhealth -LogPath:$Folder\CurrentRunDISM.log -loglevel:1)
	if(!$DismScanResults.imagehealthstate -like 'Healthy'){write-host "Attempting To Restore System Health" -foregroundcolor Green}
	$DismRestoreResults=(Repair-WindowsImage -online -restorehealth -LogPath:$Folder\CurrentRunDISM.log -loglevel:1)
	Write-host "File System Status: "$DismRestoreResults.imagehealthstate 
	if(!$DismRestoreResults.imagehealthstate -like 'Healthy'){write-host 'Need to download source files' -foregroundcolor Yellow}
}

function DownloadSource {
	$CurrentStatus = "Downloading Source System Files" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	((New-Object System.Net.WebClient).DownloadFile($File2Download,$File))
	do{$CopySize=(Get-ChildItem $File).length
	start-sleep (5)} until (((Get-ChildItem $File).length) -match $CopySize)
}

function DISMRepairSource {
	$CurrentStatus = "Running Repairs with Source Files" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()
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
	[System.Windows.Forms.Application]::DoEvents()
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
	[System.Windows.Forms.Application]::DoEvents()
	Remove-Item -Path $Folder\*.esd, $Folder\*.wim, $Folder\*.exe, $Folder\*.ps1, $Folder\*.txt
}

function RunSFC {
	$CurrentStatus = "Running System File Checker" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()
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
	[System.Windows.Forms.Application]::DoEvents()
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
	[System.Windows.Forms.Application]::DoEvents()
	ForEach($DLLF in $DLLFolders){
		$FCount=0
		$DLLList=(get-childitem $DLLF\*.dll).fullname
		$DLLList=$DLLList+(get-childitem $DLLF\*.ocx).fullname
		foreach($DFile in $DLLList){
			c:\windows\system32\regsvr32 /s %DFile
			$Percent=(($FCount/$DLLList.count) * 100)
			write-progress -Activity "Re-Registering DLLs" -PercentComplete $Percent
			$FCount+=1
		}
		$Global:DLLLog=$($Global:DLLLog + $DLLList)
	}
}

function ShowVaribles {
	$CurrentStatus = "Varibles being exported to " + $VaribleExport 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()
	(Get-Variable | format-table -autosize -wrap) | out-file $VaribleExport
}

function ScheduleRestart {
	[System.Windows.Forms.Application]::DoEvents()
	if (PendingReboot -eq "True") {
		if (!(Get-ScheduledTask | Where-Object { $_.TaskName -like '*ScheduledRestart*' } | Select-Object TaskName, State)){$RestartSchedule}
		((((get-content $PSCommandPath) | select-object -skiplast 1).replace('GUI #','AfterStartUp')).replace('[System.Windows.Forms.Application]::DoEvents()','')).replace('[void]$form.ShowDialog()','') | Out-File -FilePath $RunAfter
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
	$CurrentStatus = "Task: ScheduledRestart scheduled for " + $Date + " " + $Time
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)} else {Write-Host $CurrentStatus -foregroundcolor Green}
	} else {
	$CurrentStatus = "No Restart Needed"
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)} else {Write-Host $CurrentStatus -foregroundcolor Green}
	if ($CBCleanUp.Checked) { CleanUp }
	}
}

function Runtimes {
	$CurrentStatus = "Downloading and Installing Runtimes" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()
	foreach($Rt in $Runtimes){
		$RtFN = ($Folder + '\' + (($Rt.replace('/',' ')).split() | Where-Object {$_ -like "*.exe"}))
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		((New-Object System.Net.WebClient).DownloadFile($Rt,$RtFN))
		start-process -filepath $RtFN -ArgumentList "-quiet","-norestart"
	}
	$n=5
	do {
		$DNR="Microsoft DotNet Runtime " + $n
		$CurrentNetRuntime=winget install --id=Microsoft.DotNet.Runtime.$n  -e --silent --accept-source-agreements --disable-interactivity --include-unknown --verbose
		$NetRuntime=$NetRuntime + $DNR + $CurrentNetRuntime
		$n+=1
	} until ($n -gt 9)
	$Global:NetRuntime=switch ($NetRuntime) {{ $_.length -ge 9 } { $_ }}
}

function Update {
	$CurrentStatus = "Running Updates on Windows and Microsoft Store Apps" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()
	Install-PackageProvider -Name NuGet -Force | Out-Null
	Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery | Out-Null
	Repair-WinGetPackageManager
	Install-Module PSWindowsUpdate -Force -Repository PSGallery | Out-Null
	Import-Module PSWindowsUpdate
	Install-WindowsUpdate -MicrosoftUpdate -NotCategory 'feature pack','driver' -AcceptAll -Install -IgnoreReboot -Verbose
	$Winget = ((gci "C:\Program Files\WindowsApps" -Recurse -File | Where-Object { ($_.fullname -match 'C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_' -and $_.name -match 'winget.exe') } | sort fullname -descending | %{$_.FullName}) -Split [Environment]::NewLine)[0]
	&"$Winget" source update
	$WinGet=&"$Winget" upgrade --all --silent --accept-source-agreements  --disable-interactivity --include-unknown --verbose
	$Global:WinGet=switch ($WinGet) {{ $_.length -ge 9 } { $_ }}
}

function RemoveBadDevices {
	$CurrentStatus = "Removing Problematic Devices" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()

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
	[System.Windows.Forms.Application]::DoEvents()

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
	[System.Windows.Forms.Application]::DoEvents()
	$Global:UserScheduledTasks=(Get-ScheduledTask | Where-Object {$_.Principal.UserId -notlike "NT AUTHORITY*" -and $_.Principal.UserId -notlike "SYSTEM" -and $_.Principal.UserId -notlike "LOCAL SERVICE" -and $_.Principal.UserId -notlike "NETWORK SERVICE" -and $_.Principal.UserId -notlike $null} | Select-Object @{Name="Run As";Expression={ $_.principal.userid } }, TaskPath, TaskName)
	$Global:TimeScheduledTasks=(Get-ScheduledTask | ForEach-Object {
    $task = $_
    foreach ($trigger in $task.Triggers) {
        $startBoundary = $null
        try {
            $startBoundary = [datetime]$trigger.StartBoundary
        } catch {}

        if ($startBoundary -and $startBoundary -gt $CurrentDate) {
            [PSCustomObject]@{
                TaskName      = $task.TaskName
				TaskPath = $task.TaskPath
                'Next Run Time' = $startBoundary.ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
    }
} | Format-Table -AutoSize)
}


function PrivateNetwork {
	$CurrentStatus = "Setting Network as Private" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()

	$Global:NetworkOld = (Get-NetConnectionProfile)
	$Global:NetworkNew = (Set-NetConnectionProfile -Name $Network -NetworkCategory Private)
}

function PC-Rename {
	$CurrentStatus = "Renaming PC" 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()

	if ($CBPCRST.checked -eq "True"){
		Rename-Computer -ComputerName (Get-WmiObject win32_COMPUTERSYSTEM).Name -NewName (Get-WmiObject Win32_BIOS).serialnumber -force
	} else {
		Rename-Computer -ComputerName (Get-WmiObject win32_COMPUTERSYSTEM).Name -NewName $TXTPCR.text -Force

}
}

function RemoveDeviceGroup {

	$CurrentStatus = "Removing All Drivers for " + $DDDevices.Text 
	if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	[System.Windows.Forms.Application]::DoEvents()
	
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
		$outFile = $Folder + '\OriginalPower' + $Date + '.reg'
		$tempFile = New-TemporaryFile
		$null = reg.exe export $keyPath $tempFile /y
		$null = (Get-Content -Raw $tempFile) -match '(?s)^(.+?\])\r\n(.+?)\r\n(?:\r\n|\z)'
		Remove-Item $tempFile
		$headerLinesBlock = $Matches[1]
		$valueLinesBlock = $Matches[2]
		if ($valueLinesBlock -notmatch "(?sm)^`"$valueName`"=.+?(?=(\r\n\S|\z))") {
		#  throw "Value name not found: $valueName"
	}
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
		$CurrentStatus = "Checking System Time" 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		[System.Windows.Forms.Application]::DoEvents()

		Write-Host "Using NTP Server($NtpServer) to get time."
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
		Write-Host "Time Difference between NTP server and local system: $($([Math]::Round($Diff,2))) minutes"
		if ($Diff -gt $Max) {
			Write-Host "Time if off - Setting up NTP sync"
			Set-ItemProperty -Path 'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name Value -Value Allow
			Set-ItemProperty -Path 'HKLM:\\SYSTEM\CurrentControlSet\Services\tzautoupdate' -Name Start -Value 3
			Set-Service -Name "tzautoupdate" -StartupType Automatic
			Set-Service -Name "W32Time" -StartupType Automatic
			Start-Service -Name "tzautoupdate"
			Start-Service -Name "W32Time"
			w32tm /config /syncfromflags:manual /manualpeerlist:"time-a-g.nist.gov time-b-g.nist.gov time-c-g.nist.gov"
			w32tm /resync
		} else {Write-Host "Time is good - skipping"
		}
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

#$ServiceToChange="BrokerInfrastructure"
$ServiceToChange=$ServiceList.text
$Service = Get-Service -Name $ServiceToChange
$acl = Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
$newOwner = New-Object System.Security.Principal.NTAccount("Administrators")
$acl.SetOwner($newOwner)
Set-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)" -AclObject $acl

 

$VarD=$null
$VarS=$null
$ResultsD=$null
$ResultsS=$null
#$Service=$ServiceList.text
$AddPermissions="(A;;CCDCLCSWRPWPDTLORC;;;BA)"
$VarAccount="BA"
[string]$RawResults=sc.exe sdshow $Service
$RegexPatternALL='(D:)(\(.*\))(S:)(\(.*\))|(S:)(\(.*\))|(D:)(\(.*\))'

# Match 0 is the complete string
# Match 1 is the D: label if both sections are present
# Match 2 is the D: section permissions if both sections are present
# Match 3 is the S: label if both sections are present
# Match 4 is the S: section permissions if both sections are present
# Match 5 is the S: label if only the S: section is present
# Match 6 is the S: section permissions if only the S: section is present
# Match 7 is the D: label if only the D: section is present
# Match 8 is the D: section permissions if only the D: section is present

$RawResults -match $RegexPatternALL | out-null
#$Matches
# Find the D: section
if ($null -eq $matches[1]){
    $VarD=$Matches[8]
} else {
    $VarD=$Matches[2]
}

#Find the S: section
if ($null -eq $Matches[3]) {
    $VarS=$Matches[6]
} else {
    $VarS=$Matches[4]
}

# Split the results into individual items then strip out the open and close parenthesis from all objects.
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

# Build new SD permission string so to confirm if the values are parsed correctly.
$ExistingPermissions=$null
if ($null -ne $ResultsD){
    # This is the first element in the array
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
# Compare the newly build results with the original results (trimming whitespace).
# Only add the new permissions if we could properly build a string with the existing data which matched the original permission string.
if ($ExistingPermissions -eq $RawResults.trim()) {
    Write-Output "`nCorrectly identified existing permissions."
    # Make sure that the permissions we are setting are not already in the existing permission string.
#    if ($ExistingPermissions -notmatch $VarAccount){
        write-output "`nBuilding new permissions string..."
        $NewPermissions=$null
        if ($null -ne $ResultsD){
            # This is the first element in the array
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
#$Matches
# Find the D: section
if ($null -eq $matches[1]){
    $VarD=$Matches[8]
} else {
    $VarD=$Matches[2]
}

#Find the S: section
if ($null -eq $Matches[3]) {
    $VarS=$Matches[6]
} else {
    $VarS=$Matches[4]
}

# Split the results into individual items then strip out the open and close parenthesis from all objects.
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

# Build new SD permission string so to confirm if the values are parsed correctly.
$ExistingPermissions=$null
if ($null -ne $ResultsD){
    # This is the first element in the array
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
# Compare the newly build results with the original results (trimming whitespace).
# Only add the new permissions if we could properly build a string with the existing data which matched the original permission string.
if ($ExistingPermissions -eq $RawResults.trim()) {
    Write-Output "`nCorrectly identified existing permissions."
    # Make sure that the permissions we are setting are not already in the existing permission string.
#    if ($ExistingPermissions -notmatch $VarAccount){
        write-output "`nBuilding new permissions string..."
        $NewPermissions=$null
        if ($null -ne $ResultsD){
            # This is the first element in the array
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
#    } else {
        write-output "Permissions for this account already exist. Please review."
#    }

} else {
    write-output "`nUnable to properly parse the permission results. Please review."
}

#    } else {
        write-output "Permissions for this account already exist. Please review."
#    }

} else {
    write-output "`nUnable to properly parse the permission results. Please review."
}
}



		
		
function GUI {
	[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
	[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null

	$form = New-Object System.Windows.Forms.Form
	$Run = New-Object System.Windows.Forms.Button
	$Clear = New-Object System.Windows.Forms.Button
	$Exit = New-Object System.Windows.Forms.Button
	$Update = New-Object System.Windows.Forms.Button
	$Status = New-Object System.Windows.Forms.ListBox
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
	$CBTime = New-Object System.Windows.Forms.CheckBox
	$CBCleanUp = New-Object System.Windows.Forms.CheckBox
	$CBPCR = New-Object System.Windows.Forms.CheckBox
	$CBPCRST = New-Object System.Windows.Forms.CheckBox
	$CBVSS = New-Object System.Windows.Forms.CheckBox
	$CBSpool = New-Object System.Windows.Forms.CheckBox
	$CBDevices = New-Object System.Windows.Forms.CheckBox
	$CBEPO = New-Object System.Windows.Forms.CheckBox
	$CBServices = New-Object System.Windows.Forms.CheckBox
	$TXTPCR = New-Object System.Windows.Forms.TextBox
	$DDDevices = New-Object System.Windows.Forms.ComboBox
	$ServiceList = New-Object System.Windows.Forms.ComboBox
	
	$form.Text = "The Little Helper GUI $CurrentScriptVer"
#	$form.Size = New-Object System.Drawing.Size(375, 225)
	$form.Autosize = $True

	if ( -not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
		$CurrentStatus = "Need to run with Administrator Rights" 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
		[System.Windows.Forms.Application]::DoEvents()
	} 


	$CBCleanUp.Text = "Clean Up"
	$CBCleanUp.Location = New-Object System.Drawing.Point(10, 10)
	$CBCleanUp.Autosize = $True
	$CBCleanUp.checked = $True
	$form.Controls.Add($CBCleanUp)
	
	$CBTime.Text = "Fix Time"
	$CBTime.Location = New-Object System.Drawing.Point(10, 30)
	$CBTime.Autosize = $True
	$CBTime.checked = $True
	$form.Controls.Add($CBTime)

	$CBSpaceCleanUp.Text = "Space Clean-Up"
	$CBSpaceCleanUp.Location = New-Object System.Drawing.Point(10, 50)
	$CBSpaceCleanUp.Autosize = $True
	$CBSpaceCleanUp.checked = $True
	$form.Controls.Add($CBSpaceCleanUp)
	
	$CBNetwork.Text = "Set Network as Private"
	$CBNetwork.Location = New-Object System.Drawing.Point(10, 70)
	$CBNetwork.Autosize = $True
	$CBNetwork.checked = $True
	$form.Controls.Add($CBNetwork)

	$CBLogs.Text = "Pull Logs"
	$CBLogs.Location = New-Object System.Drawing.Point(10, 90)
	$CBLogs.Autosize = $True
	$CBLogs.checked = $True
	$form.Controls.Add($CBLogs)

	$CBDLLs.Text = "Re-Register DLLs"
	$CBDLLs.Location = New-Object System.Drawing.Point(10, 110)
	$CBDLLs.Autosize = $True
	$CBDLLs.checked = $True
	$form.Controls.Add($CBDLLs)

	$CBDISM.Text = "Run DISM"
	$CBDISM.Location = New-Object System.Drawing.Point(10, 130)
	$CBDISM.Autosize = $True
	$CBDISM.checked = $True
	$form.Controls.Add($CBDISM)

	$CBVSS.Text = "Turn On VSS"
	$CBVSS.Location = New-Object System.Drawing.Point(10, 150)
	$CBVSS.Autosize = $True
	$CBVSS.checked = $True
	$form.Controls.Add($CBVSS)

	$CBPCR.Text = "Rename PC"
	$CBPCR.Location = New-Object System.Drawing.Point(10, 170)
	$CBPCR.Autosize = $True
	$CBPCR.checked = $False
	$form.Controls.Add($CBPCR)

	$CBBadDevices.Text = "Remove Problematic Devices"
	$CBBadDevices.Location = New-Object System.Drawing.Point(160, 10)
	$CBBadDevices.Autosize = $True
	$CBBadDevices.checked = $True
	$form.Controls.Add($CBBadDevices)

	$CBSFC.Text = "Run System File Checker"
	$CBSFC.Location = New-Object System.Drawing.Point(160, 30)
	$CBSFC.Autosize = $True
	$CBSFC.checked = $True
	$form.Controls.Add($CBSFC)

	$CBRT.Text = "Install Runtimes"
	$CBRT.Location = New-Object System.Drawing.Point(160, 50)
	$CBRT.Autosize = $True
	$CBRT.checked = $True
	$form.Controls.Add($CBRT)
	
	$CBSR.Text = "Schedule Restart"
	$CBSR.Location = New-Object System.Drawing.Point(160, 70)
	$CBSR.Autosize = $True
	$CBSR.checked = $True
	$form.Controls.Add($CBSR)

	$CBST.Text = "Export Scheduled Tasks"
	$CBST.Location = New-Object System.Drawing.Point(160, 90)
	$CBST.Autosize = $True
	$CBST.checked = $True
	$form.Controls.Add($CBST)

	$CBSV.Text = "Export Varibles"
	$CBSV.Location = New-Object System.Drawing.Point(160, 110)
	$CBSV.Autosize = $True
	$CBSV.checked = $False
	$form.Controls.Add($CBSV)

	$CBCHK.Text = "Run Check Disk"
	$CBCHK.Location = New-Object System.Drawing.Point(160, 130)
	$CBCHK.Autosize = $True
	$CBCHK.checked = $True
	$form.Controls.Add($CBCHK)

	$CBSpool.Text = "Clear Spooler"
	$CBSpool.Location = New-Object System.Drawing.Point(160, 150)
	$CBSpool.Autosize = $True
	$CBSpool.checked = $True
	$form.Controls.Add($CBSpool)

	$CBPCRST.Text = "SN"
	$CBPCRST.Location = New-Object System.Drawing.Point(100, 170)
	$CBPCRST.Autosize = $True
	$CBPCRST.checked = $False
	$form.Controls.Add($CBPCRST)	
	$CBPCRST.Enabled=$False

	$CBEPO.Text = "Enable All Power Options"
	$CBEPO.Location = New-Object System.Drawing.Point(10, 190)
	$CBEPO.Autosize = $True
	$CBEPO.checked = $False
	$form.Controls.Add($CBEPO)

	$CBDevices.Text = "Remove All Devices Of"
	$CBDevices.Location = New-Object System.Drawing.Point(10, 210)
	$CBDevices.Autosize = $True
	$CBDevices.checked = $False
	$form.Controls.Add($CBDevices)	
	
#	@('AUDIOENDPOINT','BATTERY','BIOMETRIC','BLUETOOTH','CAMERA','DISKDRIVE','DISPLAY','FIRMWARE','HIDCLASS','KEYBOARD','MEDIA','MONITOR','MOUSE','NET','PRINTER','PRINTQUEUE','PROCESSOR','PROSHIELDPLUSDEVICE','SCSIADAPTER','SECURITYDEVICES','SOFTWARECOMPONENT','SOFTWAREDEVICE','SYSTEM','UCM','USB','VOLUME','VOLUMESNAPSHOT') | ForEach-Object {[void] $DDDevices.Items.Add($_)}
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
	
	@((get-service).name) | ForEach-Object {[void] $ServiceList.Items.Add($_)}
	$ServiceList.width=170
	$ServiceList.autosize = $true
	$ServiceList.location = New-Object System.Drawing.Point(160,230)
	$ServiceList.Enabled=$False
	$form.Controls.Add($ServiceList)

	$TXTPCR.Location = New-Object System.Drawing.Point(160,170)
	$TXTPCR.Size = New-Object System.Drawing.Size(75,20)
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
	$Clear.Location = New-Object System.Drawing.Point(90, 255)
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

	})


	$Update.Text = "Update"
	$Update.Location = New-Object System.Drawing.Point(170, 255)
	$Update.Add_Click({
    	AppUpdate
	})


	$Exit.Text = "Exit"
	$Exit.Location = New-Object System.Drawing.Point(250, 255)
	$Exit.Add_Click({
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
	if ($CBCleanUp.Checked) { CleanUp } #



	$Status.items.add("Run Finished")
	[System.Windows.Forms.Application]::DoEvents()
	$n=0
	do{
		$n=$n+1
		foreach ($FColor  in $FormColors) {	
		$form.BackColor = [System.Drawing.Color]::$FColor 
		Start-Sleep -Milliseconds 250
		}
	} while ($n -lt 5)
		})

	$form.Controls.Add($Run)
	$form.Controls.Add($Clear)
	$form.Controls.Add($Update)
	$form.Controls.Add($Exit)

	$Status.items.add("Form color will change once complete")
	if ($DownloadScriptVer -gt $CurrentScriptVer){
		$CurrentStatus = "Update Available" 
		if ($Status -ne $null) {$Status.items.add($CurrentStatus)}else {Write-Host $CurrentStatus -foregroundcolor Green}
	}

	$Status.Location = New-Object System.Drawing.Point(10, 290)
	$Status.Size = New-Object System.Drawing.Size(315, 100)
	$form.Controls.Add($Status)
	[void]$form.ShowDialog()
}

clear-host
start-transcript -path $Transcript -append
GUI #
#Run-Repairs
Stop-Transcript

#Written by MicrosoftSavvy

