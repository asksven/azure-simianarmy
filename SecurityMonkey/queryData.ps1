# see also https://msdn.microsoft.com/en-us/library/azure/mt704041.aspx

# read the environment variables
$Tenant           = $Env:Tenant
$ClientID         = $Env:ClientID
$ClientSecret     = $Env:ClientSecret
$Subscriptions    = $Env:Subscriptions

# check if we are all set
if ( ($Tenant -eq $null) -or ($ClientID -eq $null) -or ($ClientSecret -eq $null) -or ($Subscriptions -eq $null))
{
  Write-Output "Environment variables Tenant, ClientID, ClientSecret and Subscriptions must be set"
  exit
}

$Token            = Invoke-RestMethod -Uri https://login.microsoftonline.com/$tenant/oauth2/token?api-version=1.0 -Method Post -Body @{"grant_type" = "client_credentials"; "resource" = "https://management.core.windows.net/"; "client_id" = $ClientID; "client_secret" = $ClientSecret}

#Write-Host "Access-token: ". $Token.access_token

$subscriptionArray = $subscriptions -split ','


#Write-Host "Subscription URI: ", $subscriptionURI

$header = @{ 'authorization'="Bearer $($Token.access_token)" }

# Iterate over the subscriptions
foreach ($SubscriptionID in $subscriptionArray)
{
  # First we query alerts
  $SubscriptionURI  = "https://management.azure.com/subscriptions/$SubscriptionID/providers/microsoft.Security/alerts" +'?api-version=2015-06-01-preview'

  $Request = Invoke-RestMethod -Uri $SubscriptionURI -Headers $header -ContentType 'application/x-www-form-urlencoded'
  Write-Host "Alerts"
  #$Request
   foreach ($element in $Request.value) {
   	$element
    Write-Host "-----------------"
    $element.properties
   }

  # Then we query security statuses
  $SubscriptionURI  = "https://management.azure.com/subscriptions/$SubscriptionID/providers/microsoft.Security/securityStatuses" +'?api-version=2015-06-01-preview'

  $Request = Invoke-RestMethod -Uri $SubscriptionURI -Headers $header -ContentType 'application/x-www-form-urlencoded'
  Write-Host "Status"
  #$Request

  foreach ($element in $Request.value) {
    $element.id
   	$element.name
    $element.properties
    Write-Host ">>>>>>>"
    $element.properties.patchscannerdata

    Write-Host "-----------------"
  }
}
