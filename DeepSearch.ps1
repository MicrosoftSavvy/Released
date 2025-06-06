#Searches local drives, shadow copies and network shares
#Borrowed part of this code

if ($args[0] -ne $null){$FileName=$args[0]} else {$FileName=Read-Host "Filename to search for"}
$Drives=(get-psdrive -PSProvider 'FileSystem').root
$Path="c:\SearchResults"
if(!(test-path $Path)){New-Item -Path $Path -ItemType "directory"}
$Log=($filename.split(".")[0]) + '.log'
$SearchFile=$Path + "\" + $Log.replace('*','') 
	
Add-Type -TypeDefinition @'
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
namespace Win32
{
    public class NativeHelpers
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct IO_STATUS_BLOCK
        {
            public UInt32 Status;
            public UInt32 Information;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct NT_Trans_Data
        {
            public UInt32 NumberOfSnapShots;
            public UInt32 NumberOfSnapShotsReturned;
            public UInt32 SnapShotArraySize;
            // Omit SnapShotMultiSZ because we manually get that string based on the struct results
        }
    }
    public class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern SafeFileHandle CreateFileW(
            string lpFileName,
            FileSystemRights dwDesiredAccess,
            FileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            FileMode dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile);
        [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern UInt32 NtFsControlFile(
            SafeFileHandle hDevice,
            IntPtr Event,
            IntPtr ApcRoutine,
            IntPtr ApcContext,
            ref NativeHelpers.IO_STATUS_BLOCK IoStatusBlock,
            UInt32 FsControlCode,
            IntPtr InputBuffer,
            UInt32 InputBufferLength,
            IntPtr OutputBuffer,
            UInt32 OutputBufferLength);
        [DllImport("ntdll.dll")]
        public static extern UInt32 RtlNtStatusToDosError(
            UInt32 Status);
    }
}
'@

Function Get-LastWin32ExceptionMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Int32]
        $ErrorCode
    )
    $Exp = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $ErrorCode
    $ExpMsg = "{0} (Win32 ErrorCode {1} - 0x{1:X8})" -f $Exp.Message, $ErrorCode
    return $ExpMsg
}

Function Invoke-EnumerateSnapshots {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]
        $Handle,
        [Parameter(Mandatory = $true)]
        [System.Int32]
        $BufferSize,
        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock
    )
    $OutBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufferSize)
    try {
        $IOBlock = New-Object -TypeName Win32.NativeHelpers+IO_STATUS_BLOCK
        $Result = [Win32.NativeMethods]::NtFsControlFile($Handle, [System.IntPtr]::Zero, [System.IntPtr]::Zero,
            [System.IntPtr]::Zero, [Ref]$IOBlock, 0x00144064, [System.IntPtr]::Zero, 0, $OutBuffer, $BufferSize)
        if ($Result -ne 0) {
            # If the result was not 0 we need to convert the NTSTATUS code to a Win32 code
            $Win32Error = [Win32.NativeMethods]::RtlNtStatusToDosError($Result)
            $Msg = Get-LastWin32ExceptionMessage -ErrorCode $Win32Error
            Write-Error -Message "NtFsControlFile failed - $Msg"
            return
        }
        $TransactionData = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
            $OutBuffer,
            [Type][Win32.NativeHelpers+NT_Trans_Data]
        )
        &$ScriptBlock $OutBuffer $TransactionData
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($OutBuffer)
    }
}

Function Get-SnapshotPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path
    )

    # Automatically convert a local path to a UNC path
    if (-not ([Uri]$Path).IsUnc) {
        $Qualifier = Split-Path -Path $Path -Qualifier
        $UnqualifiedPath = Split-Path -Path $Path -NoQualifier
        $Path = '\\localhost\{0}${1}' -f $Qualifier.Substring(0, 1), $UnqualifiedPath
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Error -Message "Could not find UNC path '$Path'" -Category ObjectNotFound
        return
    }

    # Create a SafeFileHandle of the path specified and make sure it is valid
    $Handle = [Win32.NativeMethods]::CreateFileW(
        $Path,
        [System.Security.AccessControl.FileSystemRights]"ListDirectory, ReadAttributes, Synchronize",
        [System.IO.FileShare]::ReadWrite,
        [System.IntPtr]::Zero,
        [System.IO.FileMode]::Open,
        0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
        [System.IntPtr]::Zero
    )
    if ($Handle.IsInvalid) {
        $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $Msg = Get-LastWin32ExceptionMessage -ErrorCode $LastError
        Write-Error -Message "CreateFileW($Path) failed - $Msg"
        return
    }

    try {        
        # Set the initial buffer size to the size of NT_Trans_Data + 2 chars. We do this so we can get the actual buffer
        # size that is contained in the NT_Trans_Data struct. A char is 2 bytes (UTF-16) and we expect 2 of them
        $TransDataSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][Win32.NativeHelpers+NT_Trans_Data])
        $BufferSize = $TransDataSize + 4

        # Invoke NtFsControlFile at least once to get the number of snapshots and total size of the NT_Trans_Data
        # buffer. If there are 1 or more snapshots we invoke it again to get the actual snapshot strings
        Invoke-EnumerateSnapshots -Handle $Handle -BufferSize $BufferSize -ScriptBlock {
            $TransactionData = $args[1]

            if ($TransactionData.NumberOfSnapShots -gt 0) {
                # There are snapshots to retrieve, reset the buffer size to the original size + the return array size
                $NewBufferSize = $BufferSize + $TransactionData.SnapShotArraySize

                Invoke-EnumerateSnapshots -Handle $Handle -BufferSize $NewBufferSize -ScriptBlock {
                    $OutBuffer = $args[0]
                    $TransactionData = $args[1]

                    $SnapshotPtr = [System.IntPtr]::Add($OutBuffer, $TransDataSize)
                    $SnapshotString = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($SnapshotPtr,
                        $TransactionData.SnapShotArraySize / 2)

                    Write-Output -InputObject ($SnapshotString.Split([char[]]@("`0"), [System.StringSplitOptions]::RemoveEmptyEntries))
                }
            }
        } | ForEach-Object -Process { Join-Path -Path $Path -ChildPath $_ }
    } finally {
        $Handle.Dispose()
    }
}

foreach ($Drive in $Drives) {
	write-host Searching and Sorting $Drive
	$LSearch=$Drive + $FileName
	$LocalFiles = get-childitem -path $LSearch -recurse -ErrorAction "SilentlyContinue"
	$LocalList=$LocalFiles | Select-Object LastWriteTime, Length, FullName  | Sort-Object -Property LastWriteTime -Descending | format-table -autosize -wrap
	$LocalList | out-file $SearchFile -Append -force -encoding utf8
	if ((Get-SnapshotPath $Drive -ErrorAction "SilentlyContinue") -ne $null){
		$ShadowSearch=Get-SnapshotPath $Drive


		foreach ($SS in $ShadowSearch) {
			$SSearch=$SS + "\" + $FileName
			write-host Searching and Sorting $SS
			$ShadowFiles = get-childitem -path $SSearch -recurse  -ErrorAction "SilentlyContinue"
			$ShadowList=$ShadowFiles | Select-Object LastWriteTime, Length, FullName  | Sort-Object -Property LastWriteTime -Descending | format-table -autosize -wrap
			$ShadowList | out-file $SearchFile -Append -force -encoding utf8
		}
	}
}	



function Get-IpRange {

    # todo Change += to System.Collections.Arraylist

    [CmdletBinding(ConfirmImpact = 'None')]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Please enter a subnet in the form a.b.c.d/#', ValueFromPipeline, Position = 0)]
        [string[]] $Subnets
    )

    begin {
        Write-Verbose -Message "Starting [$($MyInvocation.Mycommand)]"
    }

    process {
        foreach ($subnet in $subnets) {
            if ($subnet -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
                #Split IP and subnet
                $IP = ($Subnet -split '\/')[0]
                [int] $SubnetBits = ($Subnet -split '\/')[1]
                if ($SubnetBits -lt 7 -or $SubnetBits -gt 30) {
                    Write-Error -Message 'The number following the / must be between 7 and 30'
                    break
                }
                #Convert IP into binary
                #Split IP into different octects and for each one, figure out the binary with leading zeros and add to the total
                $Octets = $IP -split '\.'
                $IPInBinary = @()
                foreach ($Octet in $Octets) {
                    #convert to binary
                    $OctetInBinary = [convert]::ToString($Octet, 2)
                    #get length of binary string add leading zeros to make octet
                    $OctetInBinary = ('0' * (8 - ($OctetInBinary).Length) + $OctetInBinary)
                    $IPInBinary = $IPInBinary + $OctetInBinary
                }
                $IPInBinary = $IPInBinary -join ''
                #Get network ID by subtracting subnet mask
                $HostBits = 32 - $SubnetBits
                $NetworkIDInBinary = $IPInBinary.Substring(0, $SubnetBits)
                #Get host ID and get the first host ID by converting all 1s into 0s
                $HostIDInBinary = $IPInBinary.Substring($SubnetBits, $HostBits)
                $HostIDInBinary = $HostIDInBinary -replace '1', '0'
                #Work out all the host IDs in that subnet by cycling through $i from 1 up to max $HostIDInBinary (i.e. 1s stringed up to $HostBits)
                #Work out max $HostIDInBinary
                $imax = [convert]::ToInt32(('1' * $HostBits), 2) - 1
                $IPs = @()
                #Next ID is first network ID converted to decimal plus $i then converted to binary
                For ($i = 1 ; $i -le $imax ; $i++) {
                    #Convert to decimal and add $i
                    $NextHostIDInDecimal = ([convert]::ToInt32($HostIDInBinary, 2) + $i)
                    #Convert back to binary
                    $NextHostIDInBinary = [convert]::ToString($NextHostIDInDecimal, 2)
                    #Add leading zeros
                    #Number of zeros to add
                    $NoOfZerosToAdd = $HostIDInBinary.Length - $NextHostIDInBinary.Length
                    $NextHostIDInBinary = ('0' * $NoOfZerosToAdd) + $NextHostIDInBinary
                    #Work out next IP
                    #Add networkID to hostID
                    $NextIPInBinary = $NetworkIDInBinary + $NextHostIDInBinary
                    #Split into octets and separate by . then join
                    $IP = @()
                    For ($x = 1 ; $x -le 4 ; $x++) {
                        #Work out start character position
                        $StartCharNumber = ($x - 1) * 8
                        #Get octet in binary
                        $IPOctetInBinary = $NextIPInBinary.Substring($StartCharNumber, 8)
                        #Convert octet into decimal
                        $IPOctetInDecimal = [convert]::ToInt32($IPOctetInBinary, 2)
                        #Add octet to IP
                        $IP += $IPOctetInDecimal
                    }
                    #Separate by .
                    $IP = $IP -join '.'
                    $IPs += $IP
                }
                Write-Output -InputObject $IPs
            } else {
                Write-Error -Message "Subnet [$subnet] is not in a valid format"
            }
        }
    }

    end {
        Write-Verbose -Message "Ending [$($MyInvocation.Mycommand)]"
    }
}


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Install-Module -Name PoshFunctions -Repository PSGallery -Force
#Import-Module -Name PoshFunctions
[string[]]$IPs=Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress
[string[]]$Subnet=Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty PrefixLength 
[string[]]$Network=(Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress,PrefixLength) | % { "$($_.IpAddress)/$($_.PrefixLength)" }
$CidrList = (Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress,PrefixLength | % { 
    $currentItem = $_
    if ($currentItem.IPAddress -notmatch "^169|^127") {
		$CidrObject = [ordered]@{
			IPAddress = "$($CurrentItem.IpAddress)";
			PreFixLength = "$($CurrentItem.PrefixLength)";
		}
        New-Object -TypeName PSObject -Property $CidrObject
    }
})
$FullList=$CidrList | %{"$($_.ipaddress)/$($_.prefixlength)"}
$IPList = foreach ($CurrentList in $FullList){Get-IpRange -Subnets $CurrentList}

foreach ($CurrentIP in $IPList) {
	if (Test-Connection $CurrentIP -count 1 -quiet){
		$IPPath="\\$($CurrentIP)"
		$Shares=(get-WmiObject -class Win32_Share -computer $CurrentIP -ErrorAction "SilentlyContinue").name 
		if ($Shares -ne $null){
			foreach ($Share in $Shares) {
			$NSearch=$IPPath + "\" + $Share + "\" + $FileName
			$NetworkPath=$IPPath + "\" + $Share
			#$NSearch
			write-host Searching and Sorting $NetworkPath
			if (test-path $NetworkPath){
				$List=get-childitem -path $NSearch -recurse -ErrorAction "SilentlyContinue"
				$FullList = $List | Select-Object LastWriteTime, Length, FullName  | Sort-Object -Property LastWriteTime -Descending | format-table -autosize -wrap
				$FullList | out-file $SearchFile -Append -force -encoding utf8
				
			}
		}
	} else {write-host $CurrentIP has no connectable shares}

	} else {write-host $CurrentIP is not pingable}
}
