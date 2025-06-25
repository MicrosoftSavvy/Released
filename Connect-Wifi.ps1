#!ps
# from https://old.reddit.com/r/msp/comments/k6do1e/windows_provisioning_packages_powershell_who/
# https://ambitions.sharefile.com/share/view/s0995d289621e41039ed2e6d059d98f41
function connectWifi {
    param (
       [Parameter(Mandatory=$False)]
       [string]$NetworkSSID,
       [Parameter(Mandatory=$true)]
       [string]$NetworkPassword,
       [ValidateSet('WEP','WPA','WPA2','WPA2PSK')]
       [Parameter(Mandatory=$False)]
       [string]$Authentication = 'WPA2PSK',
       [ValidateSet('AES','TKIP')]
       [Parameter(Mandatory=$False)]
       [string]$Encryption = 'AES'
    )

    & net.exe start wlansvc
    Start-Sleep -Seconds 2

    $output = & netsh.exe wlan show drivers
    if ($output -match "no wireless") {
        Write-Output "Wireless interface not detected."
    } else {
        # Create the WiFi profile, set the profile to auto connect
        $WirelessProfile = @'
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{0}</name>
    <SSIDConfig>
        <SSID>
            <name>{0}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{2}</authentication>
                <encryption>{3}</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{1}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
'@ -f $NetworkSSID, $NetworkPassword, $Authentication, $Encryption
        $tempWifiProfileXML = "$env:TEMP\tempWifiProfile.xml"
        $a = Set-Content -Path "$tempWifiProfileXML" -Value $WirelessProfile -Force
        Start-Process netsh.exe -ArgumentList "wlan add profile filename=`"$($tempWifiProfileXML)`"" -NoNewWindow
        $WifiNetworks = (netsh.exe wlan show network)
        If ($WifiNetworks -like "*$($NetworkSSIDSearch)*") {
            Write-Host "Found SSID: $NetworkSSID `nAttempting to connect..."
            Start-Process netsh.exe -ArgumentList "wlan connect name=`"$($NetworkSSID)`"" -NoNewWindow
            Start-Sleep 5
            & netsh.exe interface show interface
        } Else {
            Write-Host "Did not find SSID: $NetworkSSID `nConnection profile stored for later use."
        }
    }
}

connectWifi -NetworkSSID 'Verizon' -NetworkPassword 'Password123!'

