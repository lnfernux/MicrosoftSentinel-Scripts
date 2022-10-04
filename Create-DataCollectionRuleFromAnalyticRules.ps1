function Get-EventIdFromAnalyticRules {
    PARAM(
        $subscriptionId,
        $resourceGroup,
        $workspaceName
    )
    $uri = "/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${workspaceName}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-01-01-preview"
    $DownloadedRules = (Invoke-AzRestMethod -Path $uri).Content | ConvertFrom-Json -Depth 15
    $eventIds = @()
    foreach($rule in $DownloadedRules.Value) {
        $eventIdRules = $rule.properties.query | select-string -patten "EentID\s==\s[0-9]+" -AllMatches | For-EachObject {$_.Matches.Value}
        $eventIdRules = $eventIdRules -replace " ",""
        foreach($eventId in $eventIdRules) {
            $eventIds += ($eventId.Split(" ")).Split("==")[1]
        }
    }
    $uniqueEventIds = $eventIds | Sort-Object | Get-Unique
    return $uniqueEventIds
}
function New-XMLQuery {
    PARAM(
        $eventId,
        $queryId
    )
    $query = @"
<Query Id="$queryId" Path="Security">
    <Select Path="Security">*[System[(EventID=$eventId)]]</Select>
</Query>
"@
}

function New-XMLFile {
    PARAM(
        $eventIdList
    )
    $queryArray = @()
    $queryId=0
    foreach($eventId in $eventIdList) {
        $query = New-XMLQuery -eventId $eventId -queryId $queryId
        $queryArray += $query
        $queryId++
    }
    $queryFile = @"
<?xml version="1.0" encoding="utf-16"?>
<QueryList>
    $queryArray
</QueryList>
"@
}
$eventIdList = Get-EventIdFromAnalyticRules -subscriptionId subscriptionId -resourceGroup demo-rg -workspaceName demo-law
$xmlFile = New-XMLFile -eventIdList $eventIdList
$xmlFile | Out-File DCR.xml

