# Security Monkey

aims at detecting security violations and vulnerabilities using Azure Security Center.

In the future I may look into scanning apps for known framework vulnerabilities.

`getSecurityState.ps1` scans the given enviroment for security weaknesses
`queryData.ps1` is a helper dumping the JSON data returned by the Security Center API

## Setup

In order to run Security Monkey you must have set-up a service principal in your AAD and have granted permissions to the principal in your subscription(s).
At this time Security Monkey is only scanning your subscriptions: the service principal requires "Reader" permissions for `RunMode=0` and "Owner" for `RunMode=1`.

Following environment variables must be set:
- `Tenant`        : the AAD tenant ID
- `ClientID`      : the service principal's client-id 
- `ClientSecret`  : the service principal's secret
- `Subscriptions` : a comma-delimited list of subscription IDs to be scanned (the service principal must have at least reader access to those)
- `RunMode`       : (default) 0 is passive, 1 is agressive
- `SlackURL`      : can be empty, in that case nothing will get sent to slack. We use this implementation: https://github.com/asksven/azure-functions-slack-bot
- `SlackChannel`  : can be empty, default will be used in that case

SecurityMonkey can be run from the command-line but also as an Azure App WebJob. Do do so just create a zipfile containing `getSecurityState.ps1` (in the root) and deploy the zipfile to a WebJob.

## Usage

1. Set the environment variables
2. Run `getSecuritystate.ps1`

## References

On how to access the Security Center API in powershell: https://blogs.technet.microsoft.com/drew/2016/12/23/accesing-azure-security-center-api-with-powershell-invoke-restmethod/
