$Secure=(dir c:\securehost -recurse -ea SilentlyContinue).fullname
if ($Secure -ne $null) {$SecureHost=gc $Secure}
if ($Secure -eq $null) {
	$Secure="$env:temp\Securehosts"
	$SecureHost = ((invoke-webrequest "https://raw.githubusercontent.com/MicrosoftSavvy/Released/refs/heads/main/SecureHost").rawcontent).split("`n") | select -skip 26	
}
$temphostfile="$env:temp\hosts1"
$temphostfolder="$env:temp\hosts"
$temphostfile2=$temphostfolder+"\hosts"
$temphostzip="$env:temp\hosts.zip"
$WebHost1 = ((invoke-webrequest "https://hosts.ubuntu101.co.za/hosts.windows").rawcontent).split("`n") | select -skip 46
$WebHost1 = $WebHost1.replace("127.0.0.1","0.0.0.0")
$WebHost1 = $WebHost1 | Where-Object { $_ -notmatch "#" }
$WebHost1 | Out-File -FilePath $temphostfile -force -encoding utf8
if ((Select-String -path $temphostfile -Pattern "# START HOSTS LIST ### DO NOT EDIT THIS LINE AT ALL ###" -AllMatches) -ne $null) {$LineCount=(Select-String -path $temphostfile -Pattern "# START HOSTS LIST ### DO NOT EDIT THIS LINE AT ALL ###" -AllMatches).linenumber}
if ($LineCount -ne $null){$JustHost=Get-Content $temphostfile | Select -skip $LineCount} else {$JustHost=Get-Content $temphostfile}
$JustHost | Out-File -FilePath $temphostfile -force -encoding utf8
(gc $temphostfile) | ? {$_.trim() -ne "" } | set-content $temphostfile
$WebHost2 = invoke-webrequest "http://winhelp2002.mvps.org/hosts.zip" -outfile $temphostzip
Expand-Archive -Path $temphostzip -DestinationPath $temphostfolder
$JustHost2=gc $temphostfile2 
$JustHost2 | Out-File -FilePath $temphostfile2 -force -encoding utf8
$WebHost2 = $JustHost2 | Where-Object { $_ -notmatch "#" } | set-content $temphostfile2
$SH=$SecureHost + ((($Webhost1 + $WebHost2 | ? { $_ -notmatch "localhost" }) | ? { $_ -notmatch "#" })| ? { $_ -notmatch "broadcast" })
$SH=$SH | ? {$_.trim() -ne "" }
$SHUpdated = $SH | Sort-object -unique
$SHUpdated | Out-File -FilePath $Secure -force -encoding utf8
