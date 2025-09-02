$AdminEmail = "admin@customer.onmicrosoft.com"
$CSVPath="C:\Atruent\Log.csv"
#install-module -name ExchangeOnlineManagement 
#import-module -name ExchangeOnlineManagement
#Connect-IPPSSession -userprincipalname $AdminEmail
Install-Module Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force
#Import-Module Microsoft.Graph
Import-Module Microsoft.Graph.Reports
Connect-MgGraph -scopes AuditLog.Read.All
Get-MgAuditLogSignIn -Filter "Status/Errorcode ne 0" | Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, ClientAppUsed, ConditionalAccessStatus, ResourceDisplayName | Export-CSV -path $CSVPath

Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
