$script:GraphBaseUrl = 'https://graph.microsoft.com/beta/security/rules/detectionRules'
$script:AutomatedActionNames = @(
    'allowFiles', 'blockFiles', 'collectInvestigationPackages', 'disableUsers',
    'forceUserPasswordResets', 'hardDeleteEmails', 'initiateInvestigations',
    'isolateDevices', 'markUsersAsCompromised', 'moveEmailsToDeletedItems',
    'moveEmailsToInbox', 'moveEmailsToJunk', 'restrictAppExecutions',
    'runAntivirusScans', 'softDeleteEmails', 'stopAndQuarantineFiles'
)
$script:EntityMappingNames = @(
    'accounts', 'amazonResources', 'azureResources', 'cloudApplications', 'dns',
    'files', 'googleCloudResources', 'hosts', 'ips', 'mailboxes', 'mailClusters',
    'mailMessages', 'oAuthApplications', 'processes', 'registryValues',
    'securityGroups', 'urls'
)
$script:DeprecatedPropertyNames = @(
    'detectorId', 'isEnabled', 'lastRunDetails', 'period', 'nextRunDateTime',
    'scopeNames', 'scopeType', 'responseActions', 'category', 'mitreTechniques',
    'impactedAssets'
)

function Get-GraphAccessToken {
    [CmdletBinding(DefaultParameterSetName = 'AzContext')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'SPN')]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,
        [Parameter(Mandatory = $true, ParameterSetName = 'SPN')]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,
        [Parameter(Mandatory = $true, ParameterSetName = 'SPN')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId
    )

    if ($PSCmdlet.ParameterSetName -eq 'SPN') {
        try {
            $tokenResponse = Invoke-RestMethod -Method POST `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -ContentType 'application/x-www-form-urlencoded' `
                -Body @{
                    grant_type    = 'client_credentials'
                    client_id     = $ClientId
                    client_secret = $ClientSecret
                    scope         = 'https://graph.microsoft.com/.default'
                }
            return $tokenResponse.access_token
        }
        catch {
            Write-Host "ERROR: Failed to get SPN access token: $_" -ForegroundColor Red
            throw
        }
    }

    if (-not (Get-AzContext)) {
        $null = Connect-AzAccount -Identity
    }
    try {
        $tokenResponse = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/'
        return ConvertFrom-SecureString -SecureString $tokenResponse.Token -AsPlainText
    }
    catch {
        Write-Host "ERROR: Failed to get access token: $_" -ForegroundColor Red
        throw
    }
}

function Get-GraphHeader {
    param ([Parameter(Mandatory = $false)][string]$token)
    if (-not $token) {
        $token = Get-GraphAccessToken
    }
    return @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
}

function Invoke-DetectionRuleRequest {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $false)]
        [string]$Body,
        [Parameter(Mandatory = $false)]
        [string]$token
    )

    $parameters = @{ Method = $Method; Uri = $Uri }
    if ($token) {
        $parameters.Headers = Get-GraphHeader -token $token
    }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $parameters.Body = $Body
        if (-not $parameters.Headers) {
            $parameters.Headers = @{ 'Content-Type' = 'application/json' }
        }
    }
    if ($token) {
        return Invoke-RestMethod @parameters -ErrorAction Stop
    }
    return Invoke-MgGraphRequest @parameters -ErrorAction Stop
}

function Get-DetectionRules {
    param (
        [Parameter(Mandatory = $false)][string]$token,
        [Parameter(Mandatory = $false)][string]$OutputPath
    )
    try {
        $result = Invoke-DetectionRuleRequest -Method GET -Uri $script:GraphBaseUrl -token $token
    }
    catch {
        Write-Host "ERROR: Failed to get custom detection rules: $_" -ForegroundColor Red
        throw
    }
    $rules = if ($result.value) { $result.value } else { $result }
    if ($OutputPath) {
        if (-not (Test-Path $OutputPath)) {
            $null = New-Item -ItemType Directory -Path $OutputPath -Force
        }
        foreach ($rule in $rules) {
            $safeName = $rule.displayName -replace '[^\w\-\.]', '_'
            $filePath = Join-Path $OutputPath "$safeName.json"
            $rule | ConvertTo-Json -Depth 20 | Out-File -FilePath $filePath -Encoding utf8
            Write-Host "Saved: $filePath"
        }
    }
    return $rules
}

function Get-DetectionRule {
    param (
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ruleId,
        [Parameter(Mandatory = $false)][string]$token,
        [Parameter(Mandatory = $false)][string]$OutputPath
    )
    try {
        $result = Invoke-DetectionRuleRequest -Method GET -Uri "$script:GraphBaseUrl/$ruleId" -token $token
    }
    catch {
        Write-Host "ERROR: Failed to get custom detection rule $ruleId`: $_" -ForegroundColor Red
        throw
    }
    if ($OutputPath) {
        if (-not (Test-Path $OutputPath)) {
            $null = New-Item -ItemType Directory -Path $OutputPath -Force
        }
        $safeName = if ($result.displayName) { $result.displayName -replace '[^\w\-\.]', '_' } else { $ruleId }
        $filePath = Join-Path $OutputPath "$safeName.json"
        $result | ConvertTo-Json -Depth 20 | Out-File -FilePath $filePath -Encoding utf8
        Write-Host "Saved: $filePath"
    }
    return $result
}

function Test-EntityMappings {
    param ([Parameter(Mandatory = $true)][hashtable]$EntityMappings)
    foreach ($name in $EntityMappings.Keys) {
        if ($name -notin $script:EntityMappingNames) {
            throw "Invalid entity mapping '$name'. Valid mappings: $($script:EntityMappingNames -join ', ')"
        }
        if ($null -eq $EntityMappings[$name]) {
            throw "Entity mapping '$name' cannot be null."
        }
    }
    return $true
}

function Test-AutomatedActions {
    param ([Parameter(Mandatory = $true)][hashtable]$AutomatedActions)
    foreach ($name in $AutomatedActions.Keys) {
        if ($name -notin $script:AutomatedActionNames) {
            throw "Invalid automated action '$name'. Valid actions: $($script:AutomatedActionNames -join ', ')"
        }
        if ($null -eq $AutomatedActions[$name]) {
            throw "Automated action '$name' cannot be null."
        }
    }
    return $true
}

function Test-Tactics {
    param ([Parameter(Mandatory = $true)][hashtable[]]$Tactics)
    foreach ($tactic in $Tactics) {
        if (-not $tactic.tactic) {
            throw "Each tactics entry must contain a non-empty 'tactic' property."
        }
        foreach ($technique in @($tactic.techniques)) {
            if (-not $technique.technique) {
                throw "Each technique in tactic '$($tactic.tactic)' must contain a non-empty 'technique' property."
            }
        }
    }
    return $true
}

function Assert-NoDeprecatedDetectionRuleProperties {
    param ([Parameter(Mandatory = $true)]$InputObject, [string]$Path = '$')
    if ($null -eq $InputObject) {
        return
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ($key -in $script:DeprecatedPropertyNames) {
                throw "Deprecated detection rule property '$Path.$key' is not accepted."
            }
            Assert-NoDeprecatedDetectionRuleProperties -InputObject $InputObject[$key] -Path "$Path.$key"
        }
        return
    }
    if ($InputObject -is [pscustomobject]) {
        foreach ($property in $InputObject.PSObject.Properties) {
            if ($property.Name -in $script:DeprecatedPropertyNames) {
                throw "Deprecated detection rule property '$Path.$($property.Name)' is not accepted."
            }
            Assert-NoDeprecatedDetectionRuleProperties -InputObject $property.Value -Path "$Path.$($property.Name)"
        }
        return
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $index = 0
        foreach ($item in $InputObject) {
            Assert-NoDeprecatedDetectionRuleProperties -InputObject $item -Path "$Path[$index]"
            $index++
        }
    }
}

function ConvertTo-WritableDetectionRuleBody {
    param (
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][ValidateSet('Create', 'Update')][string]$Operation
    )
    Assert-NoDeprecatedDetectionRuleProperties -InputObject $InputObject
    $writableProperties = @('description', 'detectionAction', 'displayName', 'queryCondition', 'schedule', 'status')
    if ($Operation -eq 'Create') {
        $writableProperties += @('id', '@odata.type')
    }
    $body = @{}
    foreach ($property in $InputObject.PSObject.Properties) {
        if ($property.Name -in $writableProperties) {
            $body[$property.Name] = $property.Value
        }
    }
    return $body
}

function New-DetectionRule {
    [CmdletBinding(DefaultParameterSetName = 'Parameters')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'InputFile')]
        [ValidateScript({ Test-Path $_ -PathType Leaf })][string]$InputFile,
        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()][string]$id,
        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()][string]$displayName,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][string]$description,
        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateSet('enabled', 'disabled', 'autoDisabled', 'unknownFutureValue')][string]$status,
        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()][string]$queryText,
        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidatePattern('^P(?=\d|T\d)(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?$')][string]$frequency,
        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()][string]$alertTitle,
        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()][string]$alertDescription,
        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateSet('informational', 'low', 'medium', 'high')][string]$severity,
        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')][hashtable]$entityMappings,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][hashtable[]]$tactics,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][hashtable]$customDetails,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][hashtable]$automatedActions,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][string[]]$deviceGroups,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][string]$recommendedActions,
        [Parameter(Mandatory = $false)][string]$token
    )

    if ($PSCmdlet.ParameterSetName -eq 'InputFile') {
        $inputObject = Get-Content -Path $InputFile -Raw | ConvertFrom-Json
        $body = ConvertTo-WritableDetectionRuleBody -InputObject $inputObject -Operation Create
    }
    else {
        Test-EntityMappings -EntityMappings $entityMappings | Out-Null
        if ($tactics) { Test-Tactics -Tactics $tactics | Out-Null }
        if ($automatedActions) { Test-AutomatedActions -AutomatedActions $automatedActions | Out-Null }

        $alertTemplate = @{
            title = $alertTitle; description = $alertDescription; severity = $severity
            entityMappings = $entityMappings
        }
        if ($PSBoundParameters.ContainsKey('recommendedActions')) { $alertTemplate.recommendedActions = $recommendedActions }
        if ($PSBoundParameters.ContainsKey('tactics')) { $alertTemplate.tactics = @($tactics) }
        if ($PSBoundParameters.ContainsKey('customDetails')) { $alertTemplate.customDetails = $customDetails }

        $detectionAction = @{ alertTemplate = $alertTemplate }
        if ($PSBoundParameters.ContainsKey('automatedActions')) { $detectionAction.automatedActions = $automatedActions }
        if ($PSBoundParameters.ContainsKey('deviceGroups')) {
            $detectionAction.organizationalScope = @{ deviceGroups = @($deviceGroups) }
        }
        $body = @{
            '@odata.type' = '#microsoft.graph.security.detectionRule'; id = $id
            displayName = $displayName; status = $status
            queryCondition = @{ queryText = $queryText }; schedule = @{ frequency = $frequency }
            detectionAction = $detectionAction
        }
        if ($PSBoundParameters.ContainsKey('description')) { $body.description = $description }
    }

    try {
        $result = Invoke-DetectionRuleRequest -Method POST -Uri $script:GraphBaseUrl `
            -Body ($body | ConvertTo-Json -Depth 20) -token $token
    }
    catch {
        Write-Host "ERROR: Failed to create detection rule: $_" -ForegroundColor Red
        throw
    }
    Write-Host "Successfully created detection rule: $($body.displayName)" -ForegroundColor Green
    return $result
}

function Update-DetectionRule {
    [CmdletBinding(DefaultParameterSetName = 'Parameters')]
    param (
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ruleId,
        [Parameter(Mandatory = $true, ParameterSetName = 'InputFile')]
        [ValidateScript({ Test-Path $_ -PathType Leaf })][string]$InputFile,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()][string]$displayName,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][string]$description,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateSet('enabled', 'disabled', 'autoDisabled', 'unknownFutureValue')][string]$status,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()][string]$queryText,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidatePattern('^P(?=\d|T\d)(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?$')][string]$frequency,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()][string]$alertTitle,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()][string]$alertDescription,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateSet('informational', 'low', 'medium', 'high')][string]$severity,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][hashtable]$entityMappings,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][hashtable[]]$tactics,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][hashtable]$customDetails,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][hashtable]$automatedActions,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][string[]]$deviceGroups,
        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')][string]$recommendedActions,
        [Parameter(Mandatory = $false)][string]$token
    )

    if ($PSCmdlet.ParameterSetName -eq 'InputFile') {
        $inputObject = Get-Content -Path $InputFile -Raw | ConvertFrom-Json
        $body = ConvertTo-WritableDetectionRuleBody -InputObject $inputObject -Operation Update
    }
    else {
        if ($PSBoundParameters.ContainsKey('entityMappings')) { Test-EntityMappings $entityMappings | Out-Null }
        if ($PSBoundParameters.ContainsKey('tactics')) { Test-Tactics $tactics | Out-Null }
        if ($PSBoundParameters.ContainsKey('automatedActions')) { Test-AutomatedActions $automatedActions | Out-Null }

        $body = @{}
        foreach ($name in @('displayName', 'description', 'status')) {
            if ($PSBoundParameters.ContainsKey($name)) { $body[$name] = Get-Variable $name -ValueOnly }
        }
        if ($PSBoundParameters.ContainsKey('queryText')) { $body.queryCondition = @{ queryText = $queryText } }
        if ($PSBoundParameters.ContainsKey('frequency')) { $body.schedule = @{ frequency = $frequency } }

        $alertTemplate = @{}
        $alertProperties = @{
            alertTitle = 'title'; alertDescription = 'description'; severity = 'severity'
            entityMappings = 'entityMappings'; tactics = 'tactics'; customDetails = 'customDetails'
            recommendedActions = 'recommendedActions'
        }
        foreach ($parameterName in $alertProperties.Keys) {
            if ($PSBoundParameters.ContainsKey($parameterName)) {
                $value = Get-Variable $parameterName -ValueOnly
                $alertTemplate[$alertProperties[$parameterName]] = if ($parameterName -eq 'tactics') { @($value) } else { $value }
            }
        }
        $detectionAction = @{}
        if ($alertTemplate.Count) { $detectionAction.alertTemplate = $alertTemplate }
        if ($PSBoundParameters.ContainsKey('automatedActions')) { $detectionAction.automatedActions = $automatedActions }
        if ($PSBoundParameters.ContainsKey('deviceGroups')) {
            $detectionAction.organizationalScope = @{ deviceGroups = @($deviceGroups) }
        }
        if ($detectionAction.Count) { $body.detectionAction = $detectionAction }
    }
    if (-not $body.Count) { throw 'At least one writable detection rule property must be supplied.' }

    try {
        $result = Invoke-DetectionRuleRequest -Method PATCH -Uri "$script:GraphBaseUrl/$ruleId" `
            -Body ($body | ConvertTo-Json -Depth 20) -token $token
    }
    catch {
        Write-Host "ERROR: Failed to update detection rule $ruleId`: $_" -ForegroundColor Red
        throw
    }
    Write-Host "Successfully updated detection rule: $ruleId" -ForegroundColor Green
    return $result
}

function Remove-DetectionRule {
    param (
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ruleId,
        [Parameter(Mandatory = $false)][string]$token
    )
    try {
        $null = Invoke-DetectionRuleRequest -Method DELETE -Uri "$script:GraphBaseUrl/$ruleId" -token $token
    }
    catch {
        Write-Host "ERROR: Failed to delete detection rule $ruleId`: $_" -ForegroundColor Red
        throw
    }
    Write-Host "Successfully deleted detection rule: $ruleId" -ForegroundColor Green
}

Export-ModuleMember -Function @(
    'Get-GraphAccessToken', 'Get-GraphHeader', 'Get-DetectionRules', 'Get-DetectionRule',
    'New-DetectionRule', 'Update-DetectionRule', 'Remove-DetectionRule',
    'Test-EntityMappings', 'Test-AutomatedActions', 'Test-Tactics'
)