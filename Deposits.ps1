
$start=(.25)
$TotalDays=365
[double]$Piggy=0
$Days=0
[string]$PiggyBank=0
Write-host Making Daily Deposts of $Start for $TotalDays
do{
$CD=($Days * $Start)
$Piggy=($Piggy + $CD)
$CurrentDeposit='{0:C2}' -f ($CD)
$PiggyBank='{0:C2}' -f ($Piggy)
write-host Day:$Days CurrentDepsit:$CurrentDeposit PiggyBank:$PiggyBank
$Days+=1
}until ($Days -gt $TotalDays)


