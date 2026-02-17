<#
.SYNOPSIS
    Converts Azure Sentinel YAML analytic rule files to the JSON format
    returned by the Alert Rules REST API (api-version=2022-01-01-preview).

.DESCRIPTION
    Reads YAML detection rules downloaded from github.com/Azure/Azure-Sentinel
    and produces a JSON file matching the schema of:
    GET .../providers/Microsoft.SecurityInsights/alertRules?api-version=2022-01-01-preview

    Schema reference:
    https://learn.microsoft.com/rest/api/securityinsights/alert-rules/list

.PARAMETER YamlFolder
    Path to folder containing .yaml analytic rule files.

.PARAMETER OutputPath
    Path for the output JSON file.
#>
param(
    [Parameter(Mandatory)]
    [string]$YamlFolder,

    [Parameter(Mandatory)]
    [string]$OutputPath
)

Import-Module powershell-yaml -ErrorAction Stop

$yamlFiles = Get-ChildItem -Path $YamlFolder -Filter "*.yaml"
$rules = @()

foreach ($file in $yamlFiles) {
    $yaml = Get-Content $file.FullName -Raw | ConvertFrom-Yaml

    # Build the REST API response structure per:
    # https://learn.microsoft.com/rest/api/securityinsights/alert-rules/list
    $rule = [ordered]@{
        id   = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.OperationalInsights/workspaces/test-law/providers/Microsoft.SecurityInsights/alertRules/$($yaml.id)"
        name = $yaml.id
        type = "Microsoft.SecurityInsights/alertRules"
        kind = $yaml.kind ?? "Scheduled"
        etag = [guid]::NewGuid().ToString()
        properties = [ordered]@{
            alertRuleTemplateName = $null
            displayName           = $yaml.name
            description           = $yaml.description
            severity              = $yaml.severity
            enabled               = $true
            tactics               = $yaml.tactics ?? @()
            query                 = $yaml.query
            queryFrequency        = $yaml.queryFrequency
            queryPeriod           = $yaml.queryPeriod
            triggerOperator       = $yaml.triggerOperator
            triggerThreshold      = $yaml.triggerThreshold
            suppressionDuration   = "PT1H"
            suppressionEnabled    = $false
        }
    }

    $rules += $rule
}

$apiResponse = [ordered]@{
    value = $rules
}

$apiResponse | ConvertTo-Json -Depth 15 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "Converted $($rules.Count) rules to API JSON format at: $OutputPath"
