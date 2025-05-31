Set-ExecutionPolicy -executionpolicy bypass -scope Process -force
$host.UI.RawUI.WindowTitle = "The Little Tech Helper Script"

$CurrentScriptVer="1.2"
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
#$Date=Get-date -format yyyy-MM-dd
$hardwaretype=(Get-WmiObject -Class Win32_ComputerSystem -Property PCSystemType).PCSystemType
$Users= get-childitem -directory -path "c:\users"; 
$FUSFolders=@('c:\ESD','C:\Windows\SoftwareDistribution\Download','c:\ProgramData\Adobe\Temp','c:\$GetCurrent','c:\recovery','c:\windows10upgrade','C:\WINDOWS\SystemTemp\ScreenConnect') 
$Global:UserScheduledTasks
$USTLog=$Folder+"\ScheduledTasks-User.log"
$Global:TimeScheduledTasks
$NetworkLog=$Folder+"\Network.log"
$TSTLog=$Folder+"\ScheduledTasks-Timed.log"
$Network=(Get-NetConnectionProfile).Name
$FormColors="Yellow","Blue","Red","Green","LightBlue"
#$timer = New-Object System.Windows.Forms.Timer
#$timer.Interval = 500  # Set interval to 500ms (0.5 seconds)
$RunAfter=$Folder+"\Repair.ps1"
$VSSLog=$Folder+"\VSS.log"
$Global:VSSChangeLog = @()
$Spool="C:\Windows\System32\Spool"
$Spooler="C:\Windows\System32\Spool\Printers"
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
	if(!$DISMErr -eq $null){Out-File -FilePath $DISMLog -InputObject $DISMErrors.line} else {Out-File -FilePath $DISMLog -InputObject $DISMErr.line}
	$CBSContents=get-content "c:\Windows\Logs\CBS\CBS.log"  | Where-Object { $_ -GE $StartLogDate} 
	$CBSErr=$CBSContents | Select-String 'Err'
	$CBSErrors=$CBSContents | Select-String -SimpleMatch 'ERROR'
	if(!$CBSErr -eq $null){Out-File -FilePath $CBSLog -InputObject $CBSErrors.line} else {Out-File -FilePath $CBSLog -InputObject $CBSErr.line}
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
	Remove-Item -Path $Folder\*.esd, $Folder\*.wim, $Folder\*.exe, $Folder\*.ps1
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
		start-process -filepath $RtFN -ArgumentList "-silent","-norestart"
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
	
	$Script=invoke-webrequest -uri https://raw.githubusercontent.com/MicrosoftSavvy/Released/refs/heads/main/FullScript.ps1
	$DownloadScriptVer=(((($Script.rawcontent).split("`n") | Select-Object -skip 29) | Select-Object -first 1) -Replace '[^0-9.]','')
	$ScriptRaw=($Script.rawcontent).split("`n") | Select-Object -skip 26
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
	if ($CBPCRST.checked -eq "True"){
		Rename-Computer -ComputerName (Get-WmiObject win32_COMPUTERSYSTEM).Name -NewName (Get-WmiObject Win32_BIOS).serialnumber -force
	} else {
		Rename-Computer -ComputerName (Get-WmiObject win32_COMPUTERSYSTEM).Name -NewName $TXTPCR.text -Force

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
	$TXTPCR = New-Object System.Windows.Forms.TextBox

	$form.Text = "The Little Tech Helper GUI  $CurrentScriptVer"
#	$form.Size = New-Object System.Drawing.Size(375, 225)
	$form.Autosize = $True

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
	
	$CBPCRST.Add_CheckedChanged({
    if ($CBPCRST.Checked) {
	$TXTPCR.Enabled=$False
    } else {
	$TXTPCR.Enabled=$True
	}
})

	$Clear.Text = "Clear"
	$Clear.Location = New-Object System.Drawing.Point(90, 195)
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
	})


	$Update.Text = "Update"
	$Update.Location = New-Object System.Drawing.Point(170, 195)
	$Update.Add_Click({
    	AppUpdate
	})


	$Exit.Text = "Exit"
	$Exit.Location = New-Object System.Drawing.Point(250, 195)
	$Exit.Add_Click({
    	$form.Close()
	})

	$Run.Text = "Run"
	$Run.Location = New-Object System.Drawing.Point(10, 195)
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
	if ($CBSpaceCleanUp.Checked) { FreeUpSpace }
	if ($CBLogs.Checked) { Pull-Logs }
	if ($CBCleanUp.Checked) { CleanUp } #
	if ($CBSR.Checked) { ScheduleRestart }
	if ($CBPCR.Checked) { PC-Rename }
	if ($CBVSS.Checked) { VSS }
	if ($CBSpool.Checked) { Spooler }

	$Status.items.add("Run Finished")
	foreach ($FColor  in $FormColors) {	
	$form.BackColor = [System.Drawing.Color]::$FColor 
	Start-Sleep -Milliseconds 250
	}
	})

	$form.Controls.Add($Run)
	$form.Controls.Add($Clear)
	$form.Controls.Add($Update)
	$form.Controls.Add($Exit)
	
	$Status.Location = New-Object System.Drawing.Point(10, 220)
	$Status.Size = New-Object System.Drawing.Size(315, 100)
	$form.Controls.Add($Status)
	[void]$form.ShowDialog()
}

clear-host
start-transcript -path $Transcript -append
GUI #
#Run-Repairs
Stop-Transcript

#powershell -executionpolicy bypass -file d:\scripts\FullScript.ps1

