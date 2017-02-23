<# .SYNOPSIS
     SecurityMonkey is a script that scans Microsoft Azure subscription for a serie of security waeknesses. 
.DESCRIPTION
     SecurityMonkey scans your Azure subscriptions, searches for weaknesses and (optionally) takes action:
       - Use the output of Azure Security Center to report an security alerts
       - Use the output of Azure Security Center to detect unpatched VMs 
       - (optionally) stop unpatched VMs and restarts VMs waiting for a reboot 
     
     SecurityMonkey uses following environment variables:
       - Tenant           The ID of the tenant to process
       - ClientID         The client-id of the service principal
       - ClientSecret     The secret of the service principal
       - Subscriptions    A comma separated list of all subscriptions to process
       - RunMode          (default) 0 is passive, 1 is agressive
       - SlackURL         Can be empty, in that case nothing will get sent to slack. We use this implementation: https://github.com/asksven/azure-functions-slack-bot
       - SlackChannel     Can be empty, default will be used in that case

.NOTES
     Author     : asksven - sven.knispel@mail.com
.LINK
     https://github.com/asksven/azure-simianarmy
#>

Set-StrictMode -Version Latest

$Version="1.0.0"

# Hack: see https://social.msdn.microsoft.com/Forums/en-US/460eea23-3082-4b26-a3a4-38757d70853c/powershell-webjobs-and-kudu-powershell-these-dont-support-progress-bars-so-fail-on-many-commands?forum=windowsazurewebsitespreview
$ProgressPreference="SilentlyContinue" # make sure no-one tries to show a progress-bar

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

# see also https://msdn.microsoft.com/en-us/library/azure/mt704041.aspx

# read the environment variables
$Tenant           = $Env:Tenant
$ClientID         = $Env:ClientID
$ClientSecret     = $Env:ClientSecret
$Subscriptions    = $Env:Subscriptions
$RunMode          = $Env:Runmode # can be 0 (passive) or 1 (agressive), if undefined 0
$SlackURL         = $Env:SlackUrl # can be empty, in that case nothing will get sent to slack
$SlackChannel     = $Env:SlackChannel # can be empty, default will be used in that case

# Counters
$ScannedSubscriptions = 0
$ScannedVMs           = 0
$StoppedVMs           = 0
$RestartedVms         = 0

# Action, error and Findings arrays
$ActionsArray = @()
$ErrorsArray = @()
$FindingsArray = @()

# check if we are all set
if ( ($Tenant -eq $null) -or ($ClientID -eq $null) -or ($ClientSecret -eq $null) -or ($Subscriptions -eq $null))
{
  Write-Output "Environment variables Tenant, ClientID, ClientSecret and Subscriptions must be set"
  exit
}

if ( ($RunMode -eq $null) -or ($Runmode -lt 0) -or ($runMode -gt 1) )
{
  $RunMode = 0
  Write-Output "RunMode undefined or out of bounds: setting to 0"
  $ActionsArray += "RunMode was set to 0: no actions were taken"
}

$Token = Invoke-RestMethod -Uri https://login.microsoftonline.com/$tenant/oauth2/token?api-version=1.0 -Method Post -Body @{"grant_type" = "client_credentials"; "Resource" = "https://management.core.windows.net/"; "client_id" = $ClientID; "client_secret" = $ClientSecret}

$SubscriptionArray = $Subscriptions -split ','

$Header = @{ 'authorization'="Bearer $($Token.access_token)" }

# Iterate over the subscriptions
foreach ($SubscriptionID in $subscriptionArray)
{
  $ScannedSubscriptions += 1
  Write-Output "Scanning subscription $($SubscriptionID)"

  # we query security statuses
  $SecurityStateURI  = "https://management.azure.com/subscriptions/$SubscriptionID/providers/microsoft.Security/securityStatuses" +'?api-version=2015-06-01-preview'

  try
  {
    $Request = Invoke-RestMethod -Uri $SecurityStateURI -Headers $Header -ContentType 'application/x-www-form-urlencoded'
  }
  catch
  {
    Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__)"
    Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"

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

    $ScannedVMs += 1

    $ShortName = "rg=$($Resource[4]) type=$($Resource[6])/$($Resource[7]) name=$($Resource[-1])"
    Write-Output "  $($ShortName)"

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
      if ($RebootPending)
      {
        $Status = "FAIL";
        $FindingsArray += "$($ShortName) has a reboot pending"
      } 
      else
      {
        $Status="PASS";
      }

      Write-Output "    Patch Status:"
      Write-Output "      reboot pending: $($Status)"

      # if reboot s pending reboot the VM (if $RunMode is "agressive")
      if ( ($RebootPending) -and ($Runmode -eq 1) )
      {
        # see https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/virtualmachines-restart
        $VmRestartURI  = "https://management.azure.com" + $ResourceName + '/restart?api-version=2016-04-30-preview'
        try
        {
          $Response = Invoke-RestMethod -Method Post -Uri $VmRestartURI -Headers $Header -ContentType 'application/x-www-form-urlencoded'
          $RestartedVms += 1
        }
        catch
        {
          Write-Warning "StatusCode: $($_.Exception.Response.StatusCode.value__)"
          Write-Warning "StatusDescription: $($_.Exception.Response.StatusDescription)"
          $ErrorsArray += "Could not restart resource $($ShortName): $($_.Exception.Response.StatusCode.value__) : $($_.Exception.Response.StatusDescription)"
        }
        
      }

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
        Write-Warning "StatusCode: $($_.Exception.Response.StatusCode.value__)"
        Write-Warning "StatusDescription: $($_.Exception.Response.StatusDescription)"
        $ErrorsArray += "Could not access info for $($ShortName): $($_.Exception.Response.StatusCode.value__) : $($_.Exception.Response.StatusDescription)"

      }

      # if the vm is stopped we do not report a violation
      if ($VmState -ne "stopped")
      {
        if ($MissingPatches)
        {
          $Status = "FAIL"
          $FindingsArray += "$($ShortName) has has patches missing"
        }
        else
        {
          $Status = "PASS"
        }

        #Write-Host missing patches: $Status -Foreground $Color -NoNewLine
        Write-Output "      missing patches: $($Status)"

        if ($SecurityState) { $Color='red'; $Status = "FAIL"; } else {$Color='green'; $Status = "PASS"; }
        Write-Output "      security state: $($Status)"

        # if $RunMode is agressice we need to take action and stop the VM
        if ( ($MissingPatches) -and ($RunMode -eq 1) )
        {
          $VmStopURI  = "https://management.azure.com" + $ResourceName + '/powerOff?api-version=2016-04-30-preview'
          try
          {
            $Response = Invoke-RestMethod -Method Post -Uri $VmStopURI -Headers $Header -ContentType 'application/x-www-form-urlencoded'
            Write-Output ">>> Action taken: VM was stopped!"
            $StoppedVMs += 1
          }
          catch
          {
            Write-Warning -Message "StatusCode: $($_.Exception.Response.StatusCode.value__)"
            Write-Warning -Message "StatusDescription: $($_.Exception.Response.StatusDescription)"
            $ErrorsArray += "Could not stop resource $($ShortName): $($_.Exception.Response.StatusCode.value__) : $($_.Exception.Response.StatusDescription)"

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
Write-Output "--------------------------------------------------"
Write-Output "Summary:"
Write-Output "  Scanned subscriptions: $($ScannedSubscriptions)"
Write-Output "  Scanned VMs: $($ScannedSubscriptions)"
Write-Output "  Scanned VMs: $($ScannedVMs)"
Write-Output "  Stopped VMs: $($StoppedVMs)"
Write-Output "  Restarted VMs: $($RestartedVms)"

Write-Output "Actions:"
foreach ($Action in $ActionsArray)
{
  Write-Output "  $($Action)"
}

Write-Output "Errors:"
foreach ($Error in $ErrorsArray)
{
  Write-Output "  $($Error)"
}
  
Write-Output "Findings:"
foreach ($Finding in $FindingsArray)
{
  Write-Output "  $($Finding)"
}

if ($SlackURL -ne $null)
{
  $body = '{ "channel": "' + $SlackChannel + '", "username": "SecurityMonkey", "text": "Update from ' + [System.DateTime]::Now +'"'`
  + ' , "icon_url": "", "icon_emoji": ":cop:", "fallback": "Upgrade your client",' `
  + ' "notifications": ['
  # now we add status info
  $body += '{ "type": "info", "title": "Summary", "text": "I scanned ' + $ScannedSubscriptions + ' subscriptions, ' + $ScannedVMs + ' VMs and found ' + $ActionsArray.length + ' things to do." },'

  if ($StoppedVMs -gt 0)
  {
    $body += '{ "type": "info", "title": "I Stopped VMs", "text": "I stopped ' + $StoppedVMs + ' VMs" },'
  }

  if ($RestartedVMs -gt 0)
  {
    $body += '{ "type": "info", "title": "Rebooted VMs", "text": "I rebooted ' + $RestartedVms + ' VMs" },'
  }

  foreach ($Finding in $FindingsArray)
  {
        $body += '{ "type": "warn", "title": "Finding", "text": "' + $Finding + '"},'
  }

  foreach ($Error in $ErrorsArray)
  {
        $body += '{ "type": "error", "title": "Error", "text": "' + $Error + '"},'
  }

  $body += '] }'

  Invoke-RestMethod $SlackURL -Body $body -Method Post -ContentType 'application/json'
}

