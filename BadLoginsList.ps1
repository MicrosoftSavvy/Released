#!ps
#v1
#change event ID depending on what you are looking for
#4674 = escalation error
#4625 = login error

if(!(Get-Module ActiveDirectory)) { Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" } 
Get-Module -Name ActiveDirectory -ListAvailable
Import-Module -Name ActiveDirectory

Function Get-ADUserBadPasswords {
    [CmdletBinding(
        DefaultParameterSetName = 'All'
    )]
    Param (
        [Parameter(
            ValueFromPipeline = $true,
            ParameterSetName = 'ByUser'
        )]
        [Microsoft.ActiveDirectory.Management.ADUser]$Identity
        ,
        [string]$DomainController = (Get-ADDomain).PDCEmulator
        ,
        [datetime]$StartTime
        ,
        [datetime]$EndTime
    )
    Begin {
        $LogonType = @{
            '2' = 'Interactive'
            '3' = 'Network'
            '4' = 'Batch'
            '5' = 'Service'
            '7' = 'Unlock'
            '8' = 'Networkcleartext'
            '9' = 'NewCredentials'
            '10' = 'RemoteInteractive'
            '11' = 'CachedInteractive'
        }
        $filterHt = @{
            LogName = 'Security'
            ID = 4625
        }
        if ($PSBoundParameters.ContainsKey('StartTime')){
            $filterHt['StartTime'] = $StartTime
        }
        if ($PSBoundParameters.ContainsKey('EndTime')){
            $filterHt['EndTime'] = $EndTime
        }
        # Query the event log just once instead of for each user if using the pipeline
        $events = Get-WinEvent -ComputerName $DomainController -FilterHashtable $filterHt
    }
    Process {
        if ($PSCmdlet.ParameterSetName -eq 'ByUser'){
            $user = Get-ADUser $Identity
            # Filter for the user
            $output = $events | Where-Object {$_.Properties[5].Value -eq $user.SamAccountName}
        } else {
            $output = $events
        }
        foreach ($event in $output){
            [pscustomobject]@{
                TargetAccount = $event.properties.Value[5]
                LogonType = $LogonType["$($event.properties.Value[10])"]
                CallingComputer = $event.Properties.Value[13]
                IPAddress = $event.Properties.Value[19]
                TimeStamp = $event.TimeCreated
            }
        }
    }
    End{}
}


Get-ADUserBadPasswords | Format-Table

