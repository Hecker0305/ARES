# Deep Technical Procedures

## Azure Security Posture Assessment

### Subscription Enumeration
```powershell
# List all subscriptions with management group hierarchy
Get-AzSubscription | ForEach-Object { Get-AzManagementGroup -SubscriptionId $_.Id }
```

### Defender for Cloud Automation
```powershell
# Enable Defender plans across subscription
Set-AzSecurityPricing -Name "VirtualMachines" -PricingTier "Standard"
Set-AzSecurityPricing -Name "SqlServers" -PricingTier "Standard"
Set-AzSecurityPricing -Name "StorageAccounts" -PricingTier "Standard"
```

### Network Security Group Audit
```powershell
# Find NSGs with overly permissive rules
$nsgs = Get-AzNetworkSecurityGroup
$nsgs | ForEach-Object {
    $_.SecurityRules | Where-Object {
        $_.Access -eq 'Allow' -and
        $_.SourceAddressPrefix -eq '*' -and
        ($_.DestinationPortRange -eq '22' -or $_.DestinationPortRange -eq '3389' -or $_.DestinationPortRange -eq '*')
    } | Select-Object Name, DestinationPortRange, @{n='NSG';e={$_.Name}}
}
```

### Storage Account Audit
```powershell
# Check storage accounts without HTTPS-only or firewall
Get-AzStorageAccount | ForEach-Object {
    $rules = $_.NetworkRuleSet
    $props = @{
        Name = $_.StorageAccountName
        HttpsOnly = $_.EnableHttpsTrafficOnly
        FirewallEnabled = ($rules.DefaultAction -eq 'Deny')
    }
    if (-not $props.HttpsOnly -or -not $props.FirewallEnabled) {
        Write-Warning "Storage account $($_.StorageAccountName) is misconfigured"
    }
}
```

## Compliance Script Logic

```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.resource import SubscriptionClient

credential = DefaultAzureCredential()
sub_client = SubscriptionClient(credential)

for sub in sub_client.subscriptions.list():
    sec_client = SecurityCenter(credential, sub.subscription_id)
    assessments = sec_client.assessments.list(sub.subscription_id)
    for assessment in assessments:
        if assessment.status.code == 'Unhealthy':
            print(f"{sub.subscription_id}: {assessment.display_name} - FAILED")
```
