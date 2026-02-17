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
        $query = $rule.properties.query
        # Pattern 1: EventID == 4625
        $eqMatches = $query | Select-String -Pattern "EventID\s*==\s*[0-9]+" -AllMatches | ForEach-Object {$_.Matches.Value}
        foreach($match in $eqMatches) {
            $id = ($match -replace "\s","").Split("==")[1]
            $eventIds += $id
        }
        # Pattern 2: EventID in ("4728", "4732", "4756")  or  EventID in (4728, 4732)
        $inMatches = $query | Select-String -Pattern 'EventID\s+in\s*\([^)]+\)' -AllMatches | ForEach-Object {$_.Matches.Value}
        foreach($match in $inMatches) {
            $ids = [regex]::Matches($match, '[0-9]+') | ForEach-Object {$_.Value}
            $eventIds += $ids
        }
    }
    $uniqueEventIds = $eventIds | Sort-Object -Unique
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
    return $query
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
    $queriesString = $queryArray -join "`n"
    $queryFile = @"
<?xml version="1.0" encoding="utf-16"?>
<QueryList>
$queriesString
</QueryList>
"@
    return $queryFile
}
$eventIdList = Get-EventIdFromAnalyticRules -subscriptionId subscriptionId -resourceGroup demo-rg -workspaceName demo-law
$xmlFile = New-XMLFile -eventIdList $eventIdList
$xmlFile | Out-File DCR.xml

