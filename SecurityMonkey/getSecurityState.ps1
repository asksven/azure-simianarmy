<# .SYNOPSIS
     SecurityMonkey is a script that scans Microsoft Azure subscription for a serie of security waeknesses. 
.DESCRIPTION
     SecurityMonkey scans your Azure subscriptions, searches for weaknesses and (optionally) takes action:
       - Use the output of Azure Security Center to report an security alerts
       - Use the output of Azure Security Center to detect unpatched VMs 
       - (optionally) stop unpatched VMs and restarts VMs waiting for a reboot 
.NOTES
     Author     : asksven - sven.knispel@mail.com
.LINK
     https://github.com/asksven/azure-simianarmy
#>

Set-StrictMode -Version Latest

$Version="1.0.0"

Write-Output " "
Write-Output " _____                      _ _        ___  ___            _              "
Write-Output "/  ___|                    (_) |       |  \/  |           | |             "
Write-Output "\ '--.  ___  ___ _   _ _ __ _| |_ _   _| .  . | ___  _ __ | | _____ _   _ "
Write-Output " '--. \/ _ \/ __| | | | '__| | __| | | | |\/| |/ _ \| '_ \| |/ / _ \ | | |"
Write-Output "/\__/ /  __/ (__| |_| | |  | | |_| |_| | |  | | (_) | | | |   <  __/ |_| |"
Write-Output "\____/ \___|\___|\__,_|_|  |_|\__|\__, \_|  |_/\___/|_| |_|_|\_\___|\__, |"
Write-Output "                                   __/ |                             __/ |"
Write-Output "                                  |___/                             |___/ "
Write-Output "  "
Write-Output "Version $($Version)  "
Write-Output "See https://github.com/asksven/azure-simianarmy for more details"
Write-Output " "
exit
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


$Token = Invoke-RestMethod -Uri https://login.microsoftonline.com/$tenant/oauth2/token?api-version=1.0 -Method Post -Body @{"grant_type" = "client_credentials"; "Resource" = "https://management.core.windows.net/"; "client_id" = $ClientID; "client_secret" = $ClientSecret}

$SubscriptionArray = $Subscriptions -split ','

$Header = @{ 'authorization'="Bearer $($Token.access_token)" }

# Iterate over the subscriptions
foreach ($SubscriptionID in $subscriptionArray)
{

  Write-Output "Scanning subscription $($SubscriptionID)"

  # we query security statuses
  $SecurityStateURI  = "https://management.azure.com/subscriptions/$SubscriptionID/providers/microsoft.Security/securityStatuses" +'?api-version=2015-06-01-preview'

  try
  {
    $Request = Invoke-RestMethod -Uri $SecurityStateURI -Headers $Header -ContentType 'application/x-www-form-urlencoded'
  }
  catch
  {
    Write-Output "StatusCode:" $_.Exception.Response.StatusCode.value__ -Foreground 'red'
    Write-Output "StatusDescription:" $_.Exception.Response.StatusDescription -Foreground 'red'
    continue
  }
  #Write-Host "Status"
  #$Request

  # Iterate over the result set
  foreach ($Element in $Request.value)
  {
    # Element.id is a concatenation of Elements that are either constant of specific (see here: https://msdn.microsoft.com/en-us/library/azure/mt704041.aspx)
    # we are interested in:
    # - the subscription id: [2]
    # - the Resource group name: [4]
    # - the Resource type: [6]+[7]
    # - the Resourcen name: [last]
    $Resource = $Element.id -split '/'

    # Skip everything that is not a VM
    if ($Resource[6] -ne "Microsoft.Compute" -or $Resource[-1] -eq "") { continue; }

    Write-Output "  rg=$($Resource[4]) type=$($Resource[6])/$($Resource[7]) name=$($Resource[-1])"

    # Test patch status
    if ($Element.properties.patchscannerdata -ne $null)
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
      #$Element.id
     	#$Element.name

      $RebootPending = ($Element.properties.patchscannerdata.rebootPendingSecurityState -ne "Healthy")
      $MissingPatches = ($Element.properties.patchscannerdata.missingPatchesSecurityState -ne "Healthy")
      $SecurityState = ($Element.properties.patchscannerdata.securityState -ne "Healthy")

      # Parse lastReportTime
      $Template = 'yyyy-MM-dd'
      $LastReportDate = $Element.properties.patchscannerdata.lastReportTime.Split("T")[0]
      $LastReportTime = [DateTime]::ParseExact($LastReportDate, $Template, $null)
      $TimeSpan = [System.DateTime]::Now - [DateTime]$LastReportTime;
      $Age = $TimeSpan.TotalDays

      $Color = 'green';
      $Status = "OK";
      if ($RebootPending) { $Color='red'; $Status = "FAIL"; } else {$Color='green'; $Status="PASS"; }

      Write-Output "    Patch Status:"
      Write-Output "      reboot pending: $($Status)"

      # We want to check if the VM is running
      $ResourceName = ($Element.id -split("/providers/Microsoft.Security"))[0]


      # we query the VM status
      # see https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/virtualmachines-get
      $VmInfoURI  = "https://management.azure.com" + $ResourceName + '/InstanceView?api-version=2017-03-30'
      #Write-Host "Checking VM: " $VmInfoURI

      $VmState = 'unknown'

      try
      {
        $Response = Invoke-RestMethod -Uri $VmInfoURI -Headers $Header -ContentType 'application/x-www-form-urlencoded'
        if ($Response.statuses[1].code -eq "PowerState/running") {$VmState = "running"} else {$VmState = "stopped"}
      }
      catch
      {
        Write-Error "StatusCode:" $_.Exception.Response.StatusCode.value__ -Foreground 'red'
        Write-Error "StatusDescription:" $_.Exception.Response.StatusDescription -Foreground 'red'
      }

      # if the vm is stopped we do not report a violation
      if ($VmState -ne "stopped")
      {
        if ($MissingPatches) { $Color='red'; $Status = "FAIL"; } else {$Color='green'; $Status = "PASS"; }
        #Write-Host missing patches: $Status -Foreground $Color -NoNewLine
        Write-Output "      missing patches: $($Status)"

        if ($SecurityState) { $Color='red'; $Status = "FAIL"; } else {$Color='green'; $Status = "PASS"; }
        Write-Output "      security state: $($Status)"

        if ($MissingPatches)
        {
          # we need to take action and stop the VM
          $VmStopURI  = "https://management.azure.com" + $ResourceName + '/powerOff?api-version=2016-04-30-preview'
          try
          {
            $Response = Invoke-RestMethod -Method Post -Uri $VmStopURI -Headers $Header -ContentType 'application/x-www-form-urlencoded'
            Write-Output ">>> Action taken: VM was stopped!"
          }
          catch
          {
            Write-Error "StatusCode:" $_.Exception.Response.StatusCode.value__ -Foreground 'red'
            Write-Error "StatusDescription:" $_.Exception.Response.StatusDescription -Foreground 'red'
          }
        }
      }
      else
      {
        Write-Output "      missing patches: VM state is $($VmState). Ignoring"
      }
    }

    # Test vulnerability assesement status
    if ($false) # ($Element.properties.vulnerabilityAssessmentScannerStatus -ne $null)
    {
      # This is how the data looks like (*) marked items are interesting to us
      # (*) isSupported        : False
      #     dataType           : VulnerabilityAssessment
      #     isScannerDataValid : True
      #     policy             : On
      #     dataExists         : False
      # (*) securityState      : None
      #     lastReportTime     : 0001-01-01T00:00:00
      #$Element.id
     	#$Element.name
      #$Element.properties.vulnerabilityAssessmentScannerStatus
      #$Element.properties.vulnerabilityAssessmentScannerStatus.securityState
      $SupportedPass = ($Element.properties.vulnerabilityAssessmentScannerStatus.isSupported -eq "True")
      $SecurityStatePass = ($Element.properties.vulnerabilityAssessmentScannerStatus.securityState -eq "Healthy")
      Write-Output "    Vuln Scan: "
      $Color = 'green';
      $Status = "OK";
      if ($SupportedPass) {$Color='green'; $Status="PASS"; } else { $Color='red'; $Status = "FAIL"; }
      Write-Output "      vulnerability scan supported: $($Status)"

      if ($SecurityStatePass) {$Color='green'; $Status = "PASS"; } else { $Color='red'; $Status = "FAIL"; }
      Write-Output "      security state: $($Status)"

    }
  }
}
