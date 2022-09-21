# Run Connect-AzAccount + set $subscriptionid, $resourceGroup and $workspaceName
$exportPath = "C:\temp\"
$uri = "/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${workspaceName}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-01-01-preview"
$DownloadedRules = (Invoke-AzRestMethod -Path $uri).Content | ConvertFrom-Json -Depth 15
$ExportRules = @()
foreach($rule in $DownloadedRules.Value) {
    $construct = New-Object PSObject -Property @{
        displayName = $rule.properties.displayName
        description = $rule.properties.description
        severity = $rule.properties.severity
        enabled = $rule.properties.enabled    
    }
    $ExportRules += $construct
}
$ExportRules | Export-Csv -Path $exportPath
