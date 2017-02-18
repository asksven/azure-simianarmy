# Security Monkey

aims at detecting security violations and vulnerabilities using Azure Security Center.

In the future I may look into scanning apps for known framework vulnerabilities.

`getSecurityState.ps1` scans the given enviroment for security weaknesses
`queryData.ps1` is a helper dumping the JSON data returned by the Security Center API

## Setup

In order to run Security Monkey you must have set-up a service principal in your AAD and have granted permissions to the principal in your subscription(s).
At this time Security Monkey is only scanning your subscriptions: the service principal requires "Reader" permissions.

Following environment variables must be set:
- `Tenant`
- `ClientID`
- `ClientSecret`

## Usage

1. Set the environment variables
2. Run `getSecuritystate.ps1`

## References

On how to access the Security Center API in powershell: https://blogs.technet.microsoft.com/drew/2016/12/23/accesing-azure-security-center-api-with-powershell-invoke-restmethod/
