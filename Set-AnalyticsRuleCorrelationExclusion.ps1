<#
.SYNOPSIS
    Adds or removes the #DONT_CORR# tag from Sentinel analytics rules.
.DESCRIPTION
    Manages the #DONT_CORR# tag that excludes rules from Defender XDR correlation.
    Reference: https://learn.microsoft.com/en-us/defender-xdr/exclude-analytics-rules-correlation
.EXAMPLE
    .\Set-AnalyticsRuleCorrelationExclusion.ps1 -SubscriptionId "xxx" -ResourceGroup "rg-sentinel" -WorkspaceName "law-sentinel"
#>
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$WorkspaceName,
    [switch]$RemoveTag,
    [switch]$ShowAll
)

$baseUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules"
$apiVersion = "?api-version=2023-11-01"

# Get all Scheduled rules
$response = Invoke-AzRestMethod -Path "$baseUri$apiVersion" -Method GET
$rules = ($response.Content | ConvertFrom-Json).value | Where-Object { $_.kind -eq "Scheduled" }

# Filter based on mode
$filtered = if ($ShowAll) { $rules } else {
    $rules | Where-Object { 
        if ($RemoveTag) { $_.properties.description -match "^#DONT_CORR#" } 
        else { $_.properties.description -notmatch "^#DONT_CORR#" }
    }
}

if (-not $filtered) { Write-Host "No matching rules found."; exit }

# Display numbered list
$i = 1; $menu = @{}
$filtered | ForEach-Object {
    $status = if ($_.properties.enabled) { "Enabled" } else { "Disabled" }
    $corr = if ($_.properties.description -match "^#DONT_CORR#") { "EXCLUDED" } else { "CORRELATED" }
    Write-Host "$i. [$status] [$corr] $($_.properties.displayName)"
    $menu[$i++] = $_
}

# Get selection
Write-Host "`nEnter numbers (comma-separated), 'all', or 'q' to quit:"
$sel = Read-Host
if ($sel -eq 'q') { exit }

$selected = if ($sel -eq 'all') { $menu.Values } else {
    $sel -split ',' | ForEach-Object { $menu[[int]$_.Trim()] } | Where-Object { $_ }
}

if (-not $selected) { Write-Host "No valid selection."; exit }

# Confirm and process
$action = if ($RemoveTag) { "remove tag from" } else { "add tag to" }
Write-Host "`nWill $action $($selected.Count) rule(s). Continue? (y/N)"
if ((Read-Host) -notmatch '^[Yy]') { exit }

foreach ($rule in $selected) {
    $newDesc = if ($RemoveTag) { $rule.properties.description -replace "^#DONT_CORR#\s*", "" }
               else { "#DONT_CORR# " + $rule.properties.description }
    
    # Remove read-only properties
    $props = $rule.properties.PSObject.Copy()
    @('lastModifiedUtc','createdTimeUtc','alertRuleTemplateName','templateVersion') | ForEach-Object {
        $props.PSObject.Properties.Remove($_)
    }
    $props.description = $newDesc
    
    $body = @{ kind = $rule.kind; etag = $rule.etag; properties = $props } | ConvertTo-Json -Depth 10
    $result = Invoke-AzRestMethod -Path "$baseUri/$($rule.name)$apiVersion" -Method PUT -Payload $body
    
    if ($result.StatusCode -in 200,201) {
        Write-Host "[OK] $($rule.properties.displayName)"
    } else {
        Write-Host "[FAILED] $($rule.properties.displayName): $($result.Content)"
    }
}
