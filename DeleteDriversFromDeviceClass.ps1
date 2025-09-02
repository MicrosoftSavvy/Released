#!ps
# Pick Device Class from below
# DeviceClass: AUDIOENDPOINT
# DeviceClass: BATTERY
# DeviceClass: BIOMETRIC
# DeviceClass: BLUETOOTH
# DeviceClass: CAMERA
# DeviceClass: DISKDRIVE
# DeviceClass: DISPLAY
# DeviceClass: FIRMWARE
# DeviceClass: HIDCLASS
# DeviceClass: KEYBOARD
# DeviceClass: MEDIA
# DeviceClass: MONITOR
# DeviceClass: MOUSE
# DeviceClass: NET
# DeviceClass: PRINTER
# DeviceClass: PRINTQUEUE
# DeviceClass: PROCESSOR
# DeviceClass: PROSHIELDPLUSDEVICE
# DeviceClass: SCSIADAPTER
# DeviceClass: SECURITYDEVICES
# DeviceClass: SOFTWARECOMPONENT
# DeviceClass: SOFTWAREDEVICE
# DeviceClass: SYSTEM
# DeviceClass: UCM
# DeviceClass: USB
# DeviceClass: VOLUME
# DeviceClass: VOLUMESNAPSHOT


$DeviceClass="Media"
$Directory="C:\atruent\driverexport"
New-Item -Path $Directory -ItemType Directory
Start-Transcript -Path $Directory\Results.txt
$OEMList = (gwmi win32_PnPSignedDriver | ? DeviceClass -eq $DeviceClass | Select InfName)
$MediaList = (gwmi win32_PnPSignedDriver | ? DeviceClass -eq $DeviceClass | Select DeviceID)
$MediaDevice = $Directory + "\Media.txt"
$MediaDeviceList = $Directory + "\MDL.txt"
$LIST = $Directory + "\list.txt"
$LISTFULL = $Directory + "\listfull.txt"
PNPUTIL /export-driver * $Directory
write-output $MediaList > $MediaDevice
(Get-Content $MediaDevice | Select-Object -Skip 3) | Select-Object -SkipLast 2 | Set-Content $MediaDeviceList
(Get-Content -path $MediaDevice) -Replace(" ","") | out-file $MediaDeviceList
#(Get-Content -path $MediaDevice) -Replace("`n","") | out-file $MediaDeviceList
#$MDL = Get-Content -path $MediaDeviceList -Raw 
#foreach($DEVID in [System.IO.File]::ReadLines("c:\atruent\driverexport\MDL.txt")){

foreach($DEVID in [System.IO.File]::ReadLines($MediaDeviceList)){
PNPUTIL /disable-device "$DEVID"
pnputil /remove-device "$DEVID"
}

write-output $OEMList > $LISTFULL
(Get-Content $LISTFULL | Select-Object -Skip 3) | Select-Object -SkipLast 2 | Set-Content $LIST
(Get-Content -path $LIST) -Replace(" ","") | out-file $LIST
#$OEM = Get-Content $LIST -Raw 

foreach($File in [System.IO.File]::ReadLines("c:\atruent\driverexport\list.txt")){
PNPUTIL /delete-driver $File
}


Stop-Transcript
