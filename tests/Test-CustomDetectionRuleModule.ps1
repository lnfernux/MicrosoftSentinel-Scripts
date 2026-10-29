$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot '..\CustomDetectionRuleModule.psm1'

function Assert-True {
    param ([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

function global:Invoke-MgGraphRequest {
    param ($Method, $Uri, $Body, $Headers, $ErrorAction)
    $global:CapturedDetectionRuleRequest = @{
        Method = $Method
        Uri = $Uri
        Body = $Body
        Headers = $Headers
    }
    return @{ id = 'captured-rule' }
}

Import-Module $modulePath -Force

$entityMappings = @{
    accounts = @(@{ nameColumn = 'AccountName'; sidColumn = 'AccountSid' })
    hosts = @(@{ deviceIdColumn = 'DeviceId'; nameColumn = 'DeviceName' })
}
$tactics = @(
    @{ tactic = 'Execution'; techniques = @(@{ technique = 'T1059.001' }) }
)
$automatedActions = @{
    isolateDevices = @(@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' })
    initiateInvestigations = @(@{ deviceIdColumn = 'DeviceId' })
}

$null = New-DetectionRule -id 'encoded-powershell' -displayName 'Encoded PowerShell' `
    -description 'Detects encoded PowerShell.' -status enabled `
    -queryText 'DeviceProcessEvents | take 1' -frequency PT1H `
    -alertTitle 'Encoded PowerShell' -alertDescription 'Encoded PowerShell detected.' `
    -severity high -entityMappings $entityMappings -tactics $tactics `
    -customDetails @{ CommandLine = 'ProcessCommandLine' } `
    -automatedActions $automatedActions -deviceGroups @('Production')

$createBody = $global:CapturedDetectionRuleRequest.Body | ConvertFrom-Json
Assert-True ($global:CapturedDetectionRuleRequest.Method -eq 'POST') 'Create must use POST.'
Assert-True ($createBody.id -eq 'encoded-powershell') 'Create must send the required client-provided id.'
Assert-True ($createBody.status -eq 'enabled') 'Create must send status instead of isEnabled.'
Assert-True ($createBody.schedule.frequency -eq 'PT1H') 'Create must send an ISO 8601 frequency.'
Assert-True ($createBody.detectionAction.organizationalScope.deviceGroups[0] -eq 'Production') 'Create must use deviceGroups.'
Assert-True ($createBody.detectionAction.alertTemplate.entityMappings.accounts[0].sidColumn -eq 'AccountSid') 'Create must send entityMappings.'
Assert-True ($createBody.detectionAction.alertTemplate.tactics[0].techniques[0].technique -eq 'T1059.001') 'Create must send structured tactics.'
Assert-True ($createBody.detectionAction.alertTemplate.customDetails.CommandLine -eq 'ProcessCommandLine') 'Create must send customDetails.'
Assert-True ($createBody.detectionAction.automatedActions.isolateDevices[0].deviceIdColumn -eq 'DeviceId') 'Create must send grouped automatedActions.'
Assert-True ($global:CapturedDetectionRuleRequest.Body -notmatch '"(isEnabled|period|responseActions|category|mitreTechniques|impactedAssets)"') 'Create must not send deprecated properties.'
Assert-True ($global:CapturedDetectionRuleRequest.Body -notmatch '"(lookback|eventGroupingKind|incidentConfiguration)"') 'Create must leave optional settings to the API defaults.'

$null = New-DetectionRule -id 'grouped-signin' -displayName 'Grouped sign-in' -status disabled `
    -queryText 'SigninLogs | take 1' -frequency PT1H -lookback P2D -eventGroupingKind singleAlert `
    -isExcludedFromIncidentCorrelation $true -alertTitle 'Grouped sign-in' -alertDescription 'Grouped sign-in.' `
    -severity low -entityMappings @{ accounts = @(@{ aadUserIdColumn = 'UserId' }) }
$groupedBody = $global:CapturedDetectionRuleRequest.Body | ConvertFrom-Json
Assert-True ($groupedBody.schedule.lookback -eq 'P2D') 'Create must send lookback.'
Assert-True ($groupedBody.detectionAction.alertTemplate.eventGroupingKind -eq 'singleAlert') 'Create must send eventGroupingKind.'
Assert-True ($groupedBody.detectionAction.incidentConfiguration.isExcludedFromIncidentCorrelation -eq $true) 'Create must send incidentConfiguration.'

$letterIdRejected = $false
try {
    $null = New-DetectionRule -id '1-rule' -displayName 'Bad id' -status disabled -queryText 'DeviceInfo | take 1' `
        -frequency PT1H -alertTitle 'Bad id' -alertDescription 'Bad id.' -severity low -entityMappings @{}
}
catch {
    $letterIdRejected = $_.Exception.Message -match "parameter 'id'"
}
Assert-True $letterIdRejected 'Create must reject an id that does not start with a letter.'

$tacticsAccepted = Test-Tactics -Tactics @(@{ tactic = 'Execution' }, @{ tactic = 'Persistence'; techniques = @(@{ technique = 'T1053' }) })
Assert-True $tacticsAccepted 'Tactics must accept several entries and an entry without techniques.'

$null = Update-DetectionRule -ruleId 'encoded-powershell' -status disabled -frequency PT3H `
    -automatedActions @{ runAntivirusScans = @(@{ deviceIdColumn = 'DeviceId' }) }
$updateBody = $global:CapturedDetectionRuleRequest.Body | ConvertFrom-Json
Assert-True ($global:CapturedDetectionRuleRequest.Method -eq 'PATCH') 'Update must use PATCH.'
Assert-True ($updateBody.status -eq 'disabled') 'Update must send status.'
Assert-True ($updateBody.schedule.frequency -eq 'PT3H') 'Update must send frequency.'
Assert-True ($updateBody.detectionAction.automatedActions.runAntivirusScans[0].deviceIdColumn -eq 'DeviceId') 'Update must send partial automatedActions.'
Assert-True (-not $updateBody.queryCondition) 'Update must omit properties that were not supplied.'

$null = Update-DetectionRule -ruleId 'grouped-signin' -lookback P1D -eventGroupingKind alertPerEvent -isExcludedFromIncidentCorrelation $false
$groupedUpdateBody = $global:CapturedDetectionRuleRequest.Body | ConvertFrom-Json
Assert-True ($groupedUpdateBody.schedule.lookback -eq 'P1D') 'Update must send lookback.'
Assert-True ($groupedUpdateBody.detectionAction.alertTemplate.eventGroupingKind -eq 'alertPerEvent') 'Update must send eventGroupingKind.'
Assert-True ($groupedUpdateBody.detectionAction.incidentConfiguration.isExcludedFromIncidentCorrelation -eq $false) 'Update must send incidentConfiguration.'

$deprecatedInputRejected = $false
try {
    $null = New-DetectionRule -InputFile (Join-Path $PSScriptRoot 'testdata\api-examples\device-actions-rule.json')
}
catch {
    $deprecatedInputRejected = $_.Exception.Message -match 'Deprecated detection rule property'
}
Assert-True $deprecatedInputRejected 'File input must reject deprecated schema properties.'

$standaloneRoot = Join-Path $PSScriptRoot '..'
foreach ($standaloneScript in 'New-DetectionRule.ps1', 'Update-DetectionRule.ps1', 'Get-DetectionRule.ps1') {
    $scriptPath = Join-Path $standaloneRoot $standaloneScript
    Assert-True (-not (Select-String -Path $scriptPath -Pattern 'Import-Module' -Quiet)) "$standaloneScript must not import the module."
}

. (Join-Path $standaloneRoot 'New-DetectionRule.ps1')
$null = New-DetectionRule -id 'standalone-rule' -displayName 'Standalone rule' `
    -description 'Standalone rule' -queryText 'DeviceProcessEvents | take 1' `
    -frequency PT1H -techniques T1059
$standaloneCreateBody = $global:CapturedDetectionRuleRequest.Body | ConvertFrom-Json
Assert-True ($global:CapturedDetectionRuleRequest.Method -eq 'POST') 'Standalone create must use POST.'
Assert-True ($standaloneCreateBody.status -eq 'disabled') 'Standalone create must create a disabled example rule.'
Assert-True ($standaloneCreateBody.schedule.frequency -eq 'PT1H') 'Standalone create must send frequency.'
Assert-True ($standaloneCreateBody.detectionAction.alertTemplate.entityMappings.hosts[0].deviceIdColumn -eq 'DeviceId') 'Standalone create must map a host entity.'

. (Join-Path $standaloneRoot 'Update-DetectionRule.ps1')
$null = Update-DetectionRule -ruleId 'standalone-rule' -description 'Updated standalone rule' -frequency PT3H
$standaloneUpdateBody = $global:CapturedDetectionRuleRequest.Body | ConvertFrom-Json
Assert-True ($global:CapturedDetectionRuleRequest.Method -eq 'PATCH') 'Standalone update must use PATCH.'
Assert-True ($standaloneUpdateBody.description -eq 'Updated standalone rule') 'Standalone update must send description.'
Assert-True (-not $standaloneUpdateBody.queryCondition) 'Standalone update must omit unspecified properties.'

. (Join-Path $standaloneRoot 'Get-DetectionRule.ps1')
$null = Get-DetectionRule -ruleId 'standalone-rule'
Assert-True ($global:CapturedDetectionRuleRequest.Method -eq 'GET') 'Standalone get must use GET.'
Assert-True ($global:CapturedDetectionRuleRequest.Uri -match '/standalone-rule$') 'Standalone get must address the requested rule.'

function global:Invoke-MgGraphRequest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param ($Method, $Uri)
    if ($Method -ne 'GET') {
        throw "The list test expects GET, not $Method."
    }
    if ($Uri -match 'skiptoken') {
        return @{ value = @(@{ id = 'rule-b' }) }
    }
    return @{ value = @(@{ id = 'rule-a' }); '@odata.nextLink' = "$Uri`?`$skiptoken=1" }
}
$listedRules = Get-DetectionRules
Assert-True (@($listedRules).Count -eq 2) 'List must follow @odata.nextLink.'

Remove-Item Function:\Invoke-MgGraphRequest -ErrorAction SilentlyContinue
Remove-Variable CapturedDetectionRuleRequest -Scope Global -ErrorAction SilentlyContinue
Write-Host 'All custom detection rule contract tests passed.' -ForegroundColor Green