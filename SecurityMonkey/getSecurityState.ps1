# see also https://msdn.microsoft.com/en-us/library/azure/mt704041.aspx

# read the environment variables
$Tenant           = $Env:Tenant
$ClientID         = $Env:ClientID
$ClientSecret     = $Env:ClientSecret

# check if we are all set
if ( ($Tenant -eq $null) -or ($ClientID -eq $null) -or ($ClientSecret -eq $null) )
{
  Write-Output "Environment variables Tenant, ClientID and ClientSecret must be set"
  exit
}

$Token            = Invoke-RestMethod -Uri https://login.microsoftonline.com/$tenant/oauth2/token?api-version=1.0 -Method Post -Body @{"grant_type" = "client_credentials"; "resource" = "https://management.core.windows.net/"; "client_id" = $ClientID; "client_secret" = $ClientSecret}

#Write-Host "Access-token: ". $Token.access_token

$subscriptions   = "a2d270bc-d23d-4100-aba5-09a8aac81dc7,532b7299-60fb-48cd-85db-af3f17c267ff,2b9d9ac6-2bf2-4de9-b187-043f22a332d1,a273b95d-3b94-49cf-bea4-a7765d2a22ac,b1fd14d9-41da-4a83-86c5-04a862bdcb3a,82741f54-f8ce-4e38-8671-75d6bc7e7dfd,13d3dfe0-dcef-4a47-a177-c991a84c3662,99b53fb2-3e65-4f98-89b3-f6630e7e7d96"
$subscriptionArray = $subscriptions -split ','

#Write-Host "Subscription URI: ", $subscriptionURI

$header = @{ 'authorization'="Bearer $($Token.access_token)" }

# Iterate over the subscriptions
foreach ($SubscriptionID in $subscriptionArray)
{

  Write-Host "Scanning subscription $($SubscriptionID)"

  # we query security statuses
  $SubscriptionURI  = "https://management.azure.com/subscriptions/$SubscriptionID/providers/microsoft.Security/securityStatuses" +'?api-version=2015-06-01-preview'

  try
  {
    $Request = Invoke-RestMethod -Uri $SubscriptionURI -Headers $header -ContentType 'application/x-www-form-urlencoded'
  }
  catch
  {
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ -Foreground 'red'
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription -Foreground 'red'
    continue
  }
  #Write-Host "Status"
  #$Request

  # Iterate over the result set
  foreach ($element in $Request.value)
  {
    # element.id is a concatenation of elements that are either constant of specific (see here: https://msdn.microsoft.com/en-us/library/azure/mt704041.aspx)
    # we are interested in:
    # - the subscription id: [2]
    # - the resource group name: [4]
    # - the resource type: [6]+[7]
    # - the resourcen name: [last]
    $resource = $element.id -split '/'

    # Skip everything that is not a VM
    if ($resource[6] -ne "Microsoft.Compute" -or $resource[-1] -eq "") { continue; }

    Write-Host "  rg=$($resource[4]) type=$($resource[6])/$($resource[7]) name=$($resource[-1])"

    # Test patch status
    if ($element.properties.patchscannerdata -ne $null)
    {
      # This is how the data looks like (*) marked items are interesting to us
      # (*) rebootPendingSecurityState  : Healthy
      # (*) missingPatchesSecurityState : Healthy
      #     dataType                    : Patch
      #     isScannerDataValid          : True
      #     policy                      : On
      #     dataExists                  : True
      # (*) securityState               : Healthy
      #     lastReportTime              : 2017-02-11T05:29:09.67
      #$element.id
     	#$element.name

      $rebootPending = ($element.properties.patchscannerdata.rebootPendingSecurityState -ne "Healthy")
      $missingPatches = ($element.properties.patchscannerdata.missingPatchesSecurityState -ne "Healthy")
      $securityState = ($element.properties.patchscannerdata.securityState -ne "Healthy")
      #$element.properties.patchscannerdata
      Write-Host "    Patch Status: " -NoNewLine
      $color = 'green';
      $status = "OK";
      if ($rebootPending) { $color='red'; $status = "FAIL"; } else {$color='green'; $status="PASS"; }
      Write-Host reboot pending: $status -Foreground $color -NoNewLine

      Write-Host " | " -NoNewLine

      if ($missingPatches) { $color='red'; $status = "FAIL"; } else {$color='green'; $status = "PASS"; }
      Write-Host missing patches: $status -Foreground $color -NoNewLine

      Write-Host " | " -NoNewLine

      if ($securityState) { $color='red'; $status = "FAIL"; } else {$color='green'; $status = "PASS"; }
      Write-Host security state: $status -Foreground $color -NoNewLine

      Write-Host
    }

    # Test vulnerability assesement status
    if ($false) # ($element.properties.vulnerabilityAssessmentScannerStatus -ne $null)
    {
      # This is how the data looks like (*) marked items are interesting to us
      # (*) isSupported        : False
      #     dataType           : VulnerabilityAssessment
      #     isScannerDataValid : True
      #     policy             : On
      #     dataExists         : False
      # (*) securityState      : None
      #     lastReportTime     : 0001-01-01T00:00:00
      #$element.id
     	#$element.name
      #$element.properties.vulnerabilityAssessmentScannerStatus
      #$element.properties.vulnerabilityAssessmentScannerStatus.securityState
      $supportedPass = ($element.properties.vulnerabilityAssessmentScannerStatus.isSupported -eq "True")
      $securityStatePass = ($element.properties.vulnerabilityAssessmentScannerStatus.securityState -eq "Healthy")
      Write-Host "    Vuln Scan: " -NoNewLine
      $color = 'green';
      $status = "OK";
      if ($supportedPass) {$color='green'; $status="PASS"; } else { $color='red'; $status = "FAIL"; }
      Write-Host vulnerability scan supported: $status -Foreground $color -NoNewLine

      Write-Host " | " -NoNewLine

      if ($securityStatePass) {$color='green'; $status = "PASS"; } else { $color='red'; $status = "FAIL"; }
      Write-Host security state: $status -Foreground $color -NoNewLine

      Write-Host

    }
  }
}
