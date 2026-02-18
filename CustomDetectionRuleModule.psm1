$script:GraphBaseUrl = "https://graph.microsoft.com/beta/security/rules/detectionRules"

# All valid impacted asset types and their valid identifier values
# https://learn.microsoft.com/en-us/graph/api/resources/security-impactedasset?view=graph-rest-beta
$script:ImpactedAssetTypes = @{
    '#microsoft.graph.security.impactedDeviceAsset'  = @{
        ValidIdentifiers = @('deviceId', 'deviceName', 'remoteDeviceName', 'targetDeviceName', 'destinationDeviceName')
    }
    '#microsoft.graph.security.impactedUserAsset'    = @{
        ValidIdentifiers = @(
            'accountObjectId', 'accountSid', 'accountUpn', 'accountName', 'accountDomain', 'accountId',
            'requestAccountSid', 'requestAccountName', 'requestAccountDomain', 'recipientObjectId',
            'processAccountObjectId', 'initiatingAccountSid', 'initiatingProcessAccountUpn',
            'initiatingAccountName', 'initiatingAccountDomain', 'servicePrincipalId',
            'servicePrincipalName', 'targetAccountUpn'
        )
    }
    '#microsoft.graph.security.impactedMailboxAsset' = @{
        ValidIdentifiers = @(
            'accountUpn', 'fileOwnerUpn', 'initiatingProcessAccountUpn', 'lastModifyingAccountUpn',
            'targetAccountUpn', 'senderFromAddress', 'senderDisplayName', 'recipientEmailAddress',
            'senderMailFromAddress'
        )
    }
}

# All valid response action types, their identifiers, required/optional properties, and target entity
# Ref https://learn.microsoft.com/en-us/graph/api/resources/security-responseaction?view=graph-rest-beta
$script:ResponseActionTypes = @{
    #Device actions
    '#microsoft.graph.security.isolateDeviceResponseAction'               = @{
        ValidIdentifiers   = @('deviceId')
        RequiredProperties = @('isolationType')
        ValidPropertyValues = @{ isolationType = @('full', 'selective') }
        TargetEntity       = 'Device'
    }
    '#microsoft.graph.security.collectInvestigationPackageResponseAction' = @{
        ValidIdentifiers   = @('deviceId')
        RequiredProperties = @()
        TargetEntity       = 'Device'
    }
    '#microsoft.graph.security.runAntivirusScanResponseAction'            = @{
        ValidIdentifiers   = @('deviceId')
        RequiredProperties = @()
        TargetEntity       = 'Device'
    }
    '#microsoft.graph.security.initiateInvestigationResponseAction'       = @{
        ValidIdentifiers   = @('deviceId')
        RequiredProperties = @()
        TargetEntity       = 'Device'
    }
    '#microsoft.graph.security.restrictAppExecutionResponseAction'        = @{
        ValidIdentifiers   = @('deviceId')
        RequiredProperties = @()
        TargetEntity       = 'Device'
    }
    #File actions
    '#microsoft.graph.security.stopAndQuarantineFileResponseAction'       = @{
        ValidIdentifiers   = @('deviceId,sha1', 'deviceId,initiatingProcessSHA1')
        RequiredProperties = @()
        TargetEntity       = 'File'
    }
    '#microsoft.graph.security.allowFileResponseAction'                   = @{
        ValidIdentifiers     = @('sha1', 'initiatingProcessSHA1', 'sha256', 'initiatingProcessSHA256')
        RequiredProperties   = @('deviceGroupNames')
        TargetEntity         = 'File'
    }
    '#microsoft.graph.security.blockFileResponseAction'                   = @{
        ValidIdentifiers     = @('sha1', 'initiatingProcessSHA1', 'sha256', 'initiatingProcessSHA256')
        RequiredProperties   = @('deviceGroupNames')
        TargetEntity         = 'File'
    }
    # User actions
    '#microsoft.graph.security.markUserAsCompromisedResponseAction'       = @{
        ValidIdentifiers   = @('accountObjectId', 'initiatingProcessAccountObjectId', 'servicePrincipalId', 'recipientObjectId')
        RequiredProperties = @()
        TargetEntity       = 'User'
    }
    '#microsoft.graph.security.disableUserResponseAction'                 = @{
        ValidIdentifiers   = @('accountSid', 'initiatingProcessAccountSid', 'requestAccountSid', 'onPremSid')
        RequiredProperties = @()
        TargetEntity       = 'User'
    }
    '#microsoft.graph.security.forceUserPasswordResetResponseAction'      = @{
        ValidIdentifiers   = @('accountSid', 'initiatingProcessAccountSid', 'requestAccountSid', 'onPremSid')
        RequiredProperties = @()
        TargetEntity       = 'User'
    }
    # Email actions
    #NOTE: The API requires the combined identifier 'networkMessageId,recipientEmailAddress' for email actions.
    '#microsoft.graph.security.hardDeleteResponseAction'                  = @{
        ValidIdentifiers   = @('networkMessageId,recipientEmailAddress')
        RequiredProperties = @()
        TargetEntity       = 'Email'
    }
    '#microsoft.graph.security.softDeleteResponseAction'                  = @{
        ValidIdentifiers   = @('networkMessageId,recipientEmailAddress')
        RequiredProperties = @()
        TargetEntity       = 'Email'
    }
    '#microsoft.graph.security.moveToInboxResponseAction'                 = @{
        ValidIdentifiers   = @('networkMessageId,recipientEmailAddress')
        RequiredProperties = @()
        TargetEntity       = 'Email'
    }
    '#microsoft.graph.security.moveToDeletedItemsResponseAction'          = @{
        ValidIdentifiers   = @('networkMessageId,recipientEmailAddress')
        RequiredProperties = @()
        TargetEntity       = 'Email'
    }
    '#microsoft.graph.security.moveToJunkResponseAction'                  = @{
        ValidIdentifiers   = @('networkMessageId,recipientEmailAddress')
        RequiredProperties = @()
        TargetEntity       = 'Email'
    }
}

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
        Write-Host "[A] Getting Microsoft Graph API token for SPN in tenant: $TenantId"
        try {
            $body = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = $ClientSecret
                scope         = "https://graph.microsoft.com/.default"
            }
            $tokenResponse = Invoke-RestMethod -Method POST `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -ContentType "application/x-www-form-urlencoded" `
                -Body $body
            $token = $tokenResponse.access_token
            Write-Host "[*] Access token obtained successfully (SPN)"
            return $token
        }
        catch {
            Write-Host "[!] Failed to get SPN access token: $_" -ForegroundColor Red
            throw $_
        }
    }

    # Default: AzContext (managed identity / interactive)
    if (-not (Get-AzContext)) {
        Write-Host "[A] Connecting to Azure..."
        $null = Connect-AzAccount -Identity
    }
    $tenantId = (Get-AzContext).Tenant.Id
    Write-Host "[A] Getting Microsoft Graph API token for tenant: $tenantId"
    try {
        $tokenResponse = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/"
        $token = ConvertFrom-SecureString -SecureString $tokenResponse.Token -AsPlainText
        Write-Host "[*] Access token obtained successfully"
        return $token
    }
    catch {
        Write-Host "[!] Failed to get access token: $_" -ForegroundColor Red
        throw $_
    }
}

function Get-GraphHeader {
    param (
        [Parameter(Mandatory = $false)]
        [string]$token
    )
    if (-not $token) { $token = Get-GraphAccessToken }
    return @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
}

function Get-DetectionRules {
    param (
        [Parameter(Mandatory = $false)]
        [string]$token,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )
    try {
        if ($token) {
            $headers = Get-GraphHeader -token $token
            $result = Invoke-RestMethod -Method Get -Uri $script:GraphBaseUrl -Headers $headers
        }
        else {
            $result = Invoke-MgGraphRequest -Method GET -Uri $script:GraphBaseUrl
        }
    }
    catch {
        Write-Host "ERROR: Failed to get custom detection rules: $_" -ForegroundColor Red
        throw $_
    }
    $rules = if ($result.value) { $result.value } else { $result }
    if ($OutputPath) {
        if (-not (Test-Path $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath -Force }
        foreach ($rule in $rules) {
            $safeName = ($rule.displayName -replace '[^\w\-\.]', '_')
            $filePath = Join-Path $OutputPath "$safeName.json"
            $rule | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
            Write-Host "Saved: $filePath"
        }
    }
    return $rules
}

function Get-DetectionRule {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ruleId,

        [Parameter(Mandatory = $false)]
        [string]$token,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )
    $url = "$script:GraphBaseUrl/$ruleId"
    try {
        if ($token) {
            $headers = Get-GraphHeader -token $token
            $result = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
        }
        else {
            $result = Invoke-MgGraphRequest -Method GET -Uri $url
        }
    }
    catch {
        Write-Host "ERROR: Failed to get custom detection rule $ruleId`: $_" -ForegroundColor Red
        throw $_
    }
    if ($OutputPath) {
        if (-not (Test-Path $OutputPath)) { $null = New-Item -ItemType Directory -Path $OutputPath -Force }
        $safeName = if ($result.displayName) { $result.displayName -replace '[^\w\-\.]', '_' } else { $ruleId }
        $filePath = Join-Path $OutputPath "$safeName.json"
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
        Write-Host "Saved: $filePath"
    }
    return $result
}

function Test-ImpactedAsset {
    <#
    .SYNOPSIS
        Validates an impacted asset hashtable against the Graph API schema.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Asset
    )
    if (-not $Asset['@odata.type']) {
        throw "Impacted asset is missing required '@odata.type' property."
    }
    if (-not $Asset['identifier']) {
        throw "Impacted asset is missing required 'identifier' property."
    }
    $typeDef = $script:ImpactedAssetTypes[$Asset['@odata.type']]
    if (-not $typeDef) {
        $validTypes = ($script:ImpactedAssetTypes.Keys | Sort-Object) -join ", "
        throw "Invalid impacted asset type '$($Asset['@odata.type'])'. Valid types: $validTypes"
    }
    if ($Asset['identifier'] -notin $typeDef.ValidIdentifiers) {
        $validIds = ($typeDef.ValidIdentifiers | Sort-Object) -join ", "
        throw "Invalid identifier '$($Asset['identifier'])' for type '$($Asset['@odata.type'])'. Valid identifiers: $validIds"
    }
}

function Test-ResponseAction {
    <#
    .SYNOPSIS
        Validates a response action hashtable against the Graph API schema.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Action
    )
    if (-not $Action['@odata.type']) {
        throw "Response action is missing required '@odata.type' property."
    }
    if (-not $Action['identifier']) {
        throw "Response action is missing required 'identifier' property."
    }
    $typeDef = $script:ResponseActionTypes[$Action['@odata.type']]
    if (-not $typeDef) {
        $validTypes = ($script:ResponseActionTypes.Keys | Sort-Object) -join "`n  "
        throw "Invalid response action type '$($Action['@odata.type'])'. Valid types:`n  $validTypes"
    }
    if ($Action['identifier'] -notin $typeDef.ValidIdentifiers) {
        $validIds = ($typeDef.ValidIdentifiers | Sort-Object) -join ", "
        throw "Invalid identifier '$($Action['identifier'])' for action '$($Action['@odata.type'])'. Valid identifiers: $validIds"
    }
    foreach ($reqProp in $typeDef.RequiredProperties) {
        if (-not $Action[$reqProp]) {
            throw "Response action '$($Action['@odata.type'])' is missing required property '$reqProp'."
        }
    }
    if ($typeDef.ValidPropertyValues) {
        foreach ($propName in $typeDef.ValidPropertyValues.Keys) {
            if ($Action[$propName] -and $Action[$propName] -notin $typeDef.ValidPropertyValues[$propName]) {
                $validVals = ($typeDef.ValidPropertyValues[$propName] | Sort-Object) -join ", "
                throw "Invalid value '$($Action[$propName])' for property '$propName' on '$($Action['@odata.type'])'. Valid values: $validVals"
            }
        }
    }
}

function New-DetectionRule {
    <#
    .SYNOPSIS
        Creates a new custom detection rule via Microsoft Graph API.
    .DESCRIPTION
        Creates a custom detection rule using the Microsoft Graph Security API (beta).
        Supports all impacted asset types (Device, User, Mailbox) and all 16 response action types.

        IMPACTED ASSET TYPES & IDENTIFIERS:

        Device (#microsoft.graph.security.impactedDeviceAsset):
            deviceId, deviceName, remoteDeviceName, targetDeviceName, destinationDeviceName

        User (#microsoft.graph.security.impactedUserAsset):
            accountObjectId, accountSid, accountUpn, accountName, accountDomain, accountId,
            requestAccountSid, requestAccountName, requestAccountDomain, recipientObjectId,
            processAccountObjectId, initiatingAccountSid, initiatingProcessAccountUpn,
            initiatingAccountName, initiatingAccountDomain, servicePrincipalId,
            servicePrincipalName, targetAccountUpn

        Mailbox (#microsoft.graph.security.impactedMailboxAsset):
            accountUpn, fileOwnerUpn, initiatingProcessAccountUpn, lastModifyingAccountUpn,
            targetAccountUpn, senderFromAddress, senderDisplayName, recipientEmailAddress,
            senderMailFromAddress

        RESPONSE ACTION TYPES:

        Device actions (identifier: deviceId):
            #microsoft.graph.security.isolateDeviceResponseAction               (+ isolationType: full|selective)
            #microsoft.graph.security.collectInvestigationPackageResponseAction
            #microsoft.graph.security.runAntivirusScanResponseAction
            #microsoft.graph.security.initiateInvestigationResponseAction
            #microsoft.graph.security.restrictAppExecutionResponseAction

        File actions:
            #microsoft.graph.security.stopAndQuarantineFileResponseAction        (identifier: 'deviceId,sha1' or 'deviceId,initiatingProcessSHA1' - combined, comma-separated)
            #microsoft.graph.security.allowFileResponseAction                    (identifier: sha1|initiatingProcessSHA1|sha256|initiatingProcessSHA256 + REQUIRED deviceGroupNames)
            #microsoft.graph.security.blockFileResponseAction                    (identifier: sha1|initiatingProcessSHA1|sha256|initiatingProcessSHA256 + REQUIRED deviceGroupNames)

        User actions:
            #microsoft.graph.security.markUserAsCompromisedResponseAction         (identifier: accountObjectId|initiatingProcessAccountObjectId|servicePrincipalId|recipientObjectId)
            #microsoft.graph.security.disableUserResponseAction                  (identifier: accountSid|initiatingProcessAccountSid|requestAccountSid|onPremSid)
            #microsoft.graph.security.forceUserPasswordResetResponseAction        (identifier: accountSid|initiatingProcessAccountSid|requestAccountSid|onPremSid)

        Email actions (identifier: 'networkMessageId,recipientEmailAddress' - combined, comma-separated):
            #microsoft.graph.security.hardDeleteResponseAction
            #microsoft.graph.security.softDeleteResponseAction
            #microsoft.graph.security.moveToInboxResponseAction
            #microsoft.graph.security.moveToDeletedItemsResponseAction
            #microsoft.graph.security.moveToJunkResponseAction

    .PARAMETER impactedAssets
        Array of hashtables. Each must contain '@odata.type' and 'identifier'. See description for valid values.
    .PARAMETER responseActions
        Array of hashtables. Each must contain '@odata.type' and 'identifier', plus any action-specific properties. See description for valid values.
    .EXAMPLE
        # Device detection with isolate + AV scan
        $assets = @(
            @{ '@odata.type' = '#microsoft.graph.security.impactedDeviceAsset'; identifier = 'deviceId' }
        )
        $actions = @(
            @{ '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'; identifier = 'deviceId'; isolationType = 'full' },
            @{ '@odata.type' = '#microsoft.graph.security.runAntivirusScanResponseAction'; identifier = 'deviceId' }
        )
        New-DetectionRule -displayName "Suspicious Process" -isEnabled $true `
            -queryText "DeviceProcessEvents | where FileName == 'mimikatz.exe'" `
            -period "1H" -alertTitle "Mimikatz Detected" -alertDescription "Mimikatz was detected" `
            -severity "high" -category "CredentialAccess" `
            -impactedAssets $assets -responseActions $actions
    .EXAMPLE
        # User detection with mark as compromised
        $assets = @(
            @{ '@odata.type' = '#microsoft.graph.security.impactedUserAsset'; identifier = 'accountObjectId' }
        )
        $actions = @(
            @{ '@odata.type' = '#microsoft.graph.security.markUserAsCompromisedResponseAction'; identifier = 'accountObjectId' },
            @{ '@odata.type' = '#microsoft.graph.security.disableUserResponseAction'; identifier = 'accountSid' }
        )
        New-DetectionRule -displayName "Compromised User" -isEnabled $true `
            -queryText "IdentityLogonEvents | where ..." -period "1H" `
            -alertTitle "User Compromised" -alertDescription "User account compromised" `
            -severity "high" -category "CredentialAccess" `
            -impactedAssets $assets -responseActions $actions
    .EXAMPLE
        # Email detection with hard delete
        $assets = @(
            @{ '@odata.type' = '#microsoft.graph.security.impactedMailboxAsset'; identifier = 'recipientEmailAddress' }
        )
        $actions = @(
            @{ '@odata.type' = '#microsoft.graph.security.hardDeleteResponseAction'; identifier = 'networkMessageId,recipientEmailAddress' }
        )
        New-DetectionRule -displayName "Phishing Remediation" -isEnabled $true `
            -queryText "EmailEvents | where ..." -period "1H" `
            -alertTitle "Phishing Email" -alertDescription "Phishing email detected" `
            -severity "high" -category "InitialAccess" `
            -impactedAssets $assets -responseActions $actions
    .EXAMPLE
        # File block with device group scoping
        $assets = @(
            @{ '@odata.type' = '#microsoft.graph.security.impactedDeviceAsset'; identifier = 'deviceId' }
        )
        $actions = @(
            @{ '@odata.type' = '#microsoft.graph.security.blockFileResponseAction'; identifier = 'sha256'; deviceGroupNames = @('Production') }
        )
        New-DetectionRule -displayName "Block Malware Hash" -isEnabled $true `
            -queryText "DeviceFileEvents | where SHA256 == '...'" -period "1H" `
            -alertTitle "Malware File" -alertDescription "Known malware file detected" `
            -severity "high" -category "Malware" `
            -impactedAssets $assets -responseActions $actions
    #>
    [CmdletBinding(DefaultParameterSetName = 'Parameters')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'InputFile')]
        [ValidateScript({ Test-Path $_ })]
        [string]$InputFile,

        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()]
        [string]$displayName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [bool]$isEnabled,

        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()]
        [string]$queryText,

        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateSet("0", "NRT", "1H", "3H", "12H", "24H")]
        [string]$period,

        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()]
        [string]$alertTitle,

        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()]
        [string]$alertDescription,

        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateSet("informational", "low", "medium", "high")]
        [string]$severity,

        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateSet(
            "Malware", "Execution", "Discovery", "Lateral Movement", "Persistence",
            "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Collection",
            "Exfiltration", "CommandAndControl", "SuspiciousActivity", "Unwanted Software",
            "Ransomware", "Exploit", "Impact", "InitialAccess", "Reconnaissance", "ResourceDevelopment"
        )]
        [string]$category,

        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()]
        [hashtable[]]$impactedAssets,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [hashtable[]]$responseActions,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [string[]]$mitreTechniques,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        $recommendedActions,

        [Parameter(Mandatory = $false)]
        [string]$token
    )

    if ($PSCmdlet.ParameterSetName -eq 'InputFile') {
        $jsonContent = Get-Content -Path $InputFile -Raw | ConvertFrom-Json
        $body = @{}
        foreach ($prop in $jsonContent.PSObject.Properties) {
            if ($prop.Name -notin @('id', '@odata.context', 'createdDateTime', 'lastModifiedDateTime', 'wasRecentlyDeactivated', 'lastRunDetails')) {
                $body[$prop.Name] = $prop.Value
            }
        }
        $jsonBody = $body | ConvertTo-Json -Depth 10
        try {
            if ($token) {
                $headers = Get-GraphHeader -token $token
                $result = Invoke-RestMethod -Method POST -Uri $script:GraphBaseUrl -Body $jsonBody -Headers $headers
            }
            else {
                $result = Invoke-MgGraphRequest -Method POST -Uri $script:GraphBaseUrl -Body $jsonBody -Headers @{ "Content-Type" = "application/json" }
            }
        }
        catch {
            Write-Host "ERROR: Failed to create detection rule from file: $_" -ForegroundColor Red
            throw $_
        }
        Write-Host "Successfully created detection rule from file: $InputFile" -ForegroundColor Green
        return $result
    }

    # Validate impacted assets
    foreach ($asset in $impactedAssets) {
        Test-ImpactedAsset -Asset $asset
    }

    # Validate response actions
    $validatedActions = @()
    if ($PSBoundParameters.ContainsKey('responseActions') -and $responseActions) {
        foreach ($action in $responseActions) {
            Test-ResponseAction -Action $action
        }
        $validatedActions = $responseActions
    }

    # Map NRT to API value "0"
    $schedulePeriod = if ($period -eq 'NRT') { '0' } else { $period }

    $body = @{
        displayName    = $displayName
        isEnabled      = $isEnabled
        queryCondition = @{
            queryText = $queryText
        }
        schedule = @{
            period = $schedulePeriod
        }
        detectionAction = @{
            alertTemplate = @{
                title          = $alertTitle
                description    = $alertDescription
                severity       = $severity.ToLower()
                category       = $category
                impactedAssets = @($impactedAssets)
            }
            organizationalScope = $null
            responseActions     = @($validatedActions)
        }
    }

    if ($PSBoundParameters.ContainsKey('mitreTechniques') -and $mitreTechniques.Count -gt 0) {
        $body.detectionAction.alertTemplate.mitreTechniques = $mitreTechniques
    }
    if ($PSBoundParameters.ContainsKey('recommendedActions') -and $recommendedActions) {
        $body.detectionAction.alertTemplate.recommendedActions = $recommendedActions
    }

    $jsonBody = $body | ConvertTo-Json -Depth 10

    try {
        if ($token) {
            $headers = Get-GraphHeader -token $token
            $result = Invoke-RestMethod -Method POST -Uri $script:GraphBaseUrl -Body $jsonBody -Headers $headers
        }
        else {
            $result = Invoke-MgGraphRequest -Method POST -Uri $script:GraphBaseUrl -Body $jsonBody -Headers @{ "Content-Type" = "application/json" }
        }
    }
    catch {
        Write-Host "ERROR: Failed to create detection rule: $_" -ForegroundColor Red
        throw $_
    }
    Write-Host "Successfully created detection rule: $displayName" -ForegroundColor Green
    return $result
}

function Update-DetectionRule {
    <#
    .SYNOPSIS
        Updates an existing custom detection rule via Microsoft Graph API.
    .DESCRIPTION
        Updates a custom detection rule using PATCH. Only specified parameters are updated.
        Supports all impacted asset types and response action types.
        See New-DetectionRule for full documentation of asset types and response actions.
    .PARAMETER ruleId
        The ID of the detection rule to update.
    .PARAMETER impactedAssets
        Array of hashtables. Each must contain '@odata.type' and 'identifier'.
    .PARAMETER responseActions
        Array of hashtables. Each must contain '@odata.type' and 'identifier', plus action-specific properties.
    .EXAMPLE
        # Change response actions to also disable the user
        $actions = @(
            @{ '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'; identifier = 'deviceId'; isolationType = 'full' },
            @{ '@odata.type' = '#microsoft.graph.security.disableUserResponseAction'; identifier = 'accountSid' }
        )
        Update-DetectionRule -ruleId '12345' -responseActions $actions
    #>
    [CmdletBinding(DefaultParameterSetName = 'Parameters')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ruleId,

        [Parameter(Mandatory = $true, ParameterSetName = 'InputFile')]
        [ValidateScript({ Test-Path $_ })]
        [string]$InputFile,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()]
        [string]$displayName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [bool]$isEnabled,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()]
        [string]$queryText,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateSet("0", "NRT", "1H", "3H", "12H", "24H")]
        [string]$period,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()]
        [string]$alertTitle,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()]
        [string]$alertDescription,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateSet("informational", "low", "medium", "high")]
        [string]$severity,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateSet(
            "Malware", "Execution", "Discovery", "Lateral Movement", "Persistence",
            "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Collection",
            "Exfiltration", "CommandAndControl", "SuspiciousActivity", "Unwanted Software",
            "Ransomware", "Exploit", "Impact", "InitialAccess", "Reconnaissance", "ResourceDevelopment"
        )]
        [string]$category,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [hashtable[]]$impactedAssets,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [hashtable[]]$responseActions,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [string[]]$mitreTechniques,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        $recommendedActions,

        [Parameter(Mandatory = $false)]
        [string]$token
    )

    if ($PSCmdlet.ParameterSetName -eq 'InputFile') {
        $jsonContent = Get-Content -Path $InputFile -Raw | ConvertFrom-Json
        $body = @{}
        foreach ($prop in $jsonContent.PSObject.Properties) {
            if ($prop.Name -notin @('id', '@odata.context', 'createdDateTime', 'lastModifiedDateTime', 'wasRecentlyDeactivated', 'lastRunDetails')) {
                $body[$prop.Name] = $prop.Value
            }
        }
        $jsonBody = $body | ConvertTo-Json -Depth 10
        $url = "$script:GraphBaseUrl/$ruleId"
        try {
            if ($token) {
                $headers = Get-GraphHeader -token $token
                $result = Invoke-RestMethod -Method PATCH -Uri $url -Body $jsonBody -Headers $headers
            }
            else {
                $result = Invoke-MgGraphRequest -Method PATCH -Uri $url -Body $jsonBody -Headers @{ "Content-Type" = "application/json" }
            }
        }
        catch {
            Write-Host "ERROR: Failed to update detection rule $ruleId from file: $_" -ForegroundColor Red
            throw $_
        }
        Write-Host "Successfully updated detection rule $ruleId from file: $InputFile" -ForegroundColor Green
        return $result
    }

    # Validate impacted assets if provided
    if ($PSBoundParameters.ContainsKey('impactedAssets')) {
        foreach ($asset in $impactedAssets) {
            Test-ImpactedAsset -Asset $asset
        }
    }

    # Validate response actions if provided
    if ($PSBoundParameters.ContainsKey('responseActions') -and $responseActions) {
        foreach ($action in $responseActions) {
            Test-ResponseAction -Action $action
        }
    }

    $body = @{}

    if ($PSBoundParameters.ContainsKey('displayName')) {
        $body.displayName = $displayName
    }
    if ($PSBoundParameters.ContainsKey('isEnabled')) {
        $body.isEnabled = $isEnabled
    }
    if ($PSBoundParameters.ContainsKey('queryText')) {
        $body.queryCondition = @{ queryText = $queryText }
    }
    if ($PSBoundParameters.ContainsKey('period')) {
        $schedulePeriod = if ($period -eq 'NRT') { '0' } else { $period }
        $body.schedule = @{ period = $schedulePeriod }
    }

    $alertTemplate = @{}

    if ($PSBoundParameters.ContainsKey('alertTitle')) {
        $alertTemplate.title = $alertTitle
    }
    if ($PSBoundParameters.ContainsKey('alertDescription')) {
        $alertTemplate.description = $alertDescription
    }
    if ($PSBoundParameters.ContainsKey('severity')) {
        $alertTemplate.severity = $severity.ToLower()
    }
    if ($PSBoundParameters.ContainsKey('category')) {
        $alertTemplate.category = $category
    }
    if ($PSBoundParameters.ContainsKey('recommendedActions')) {
        $alertTemplate.recommendedActions = $recommendedActions
    }
    if ($PSBoundParameters.ContainsKey('mitreTechniques')) {
        $alertTemplate.mitreTechniques = $mitreTechniques
    }
    if ($PSBoundParameters.ContainsKey('impactedAssets')) {
        $alertTemplate.impactedAssets = @($impactedAssets)
    }

    $detectionAction = @{}
    if ($alertTemplate.Count -gt 0) {
        $detectionAction.alertTemplate = $alertTemplate
    }
    if ($PSBoundParameters.ContainsKey('responseActions')) {
        $detectionAction.responseActions = @($responseActions)
    }
    if ($detectionAction.Count -gt 0) {
        $body.detectionAction = $detectionAction
    }

    $jsonBody = $body | ConvertTo-Json -Depth 10
    $url = "$script:GraphBaseUrl/$ruleId"

    try {
        if ($token) {
            $headers = Get-GraphHeader -token $token
            $result = Invoke-RestMethod -Method PATCH -Uri $url -Body $jsonBody -Headers $headers
        }
        else {
            $result = Invoke-MgGraphRequest -Method PATCH -Uri $url -Body $jsonBody -Headers @{ "Content-Type" = "application/json" }
        }
    }
    catch {
        Write-Host "ERROR: Failed to update detection rule $ruleId`: $_" -ForegroundColor Red
        throw $_
    }
    Write-Host "Successfully updated detection rule: $ruleId" -ForegroundColor Green
    return $result
}

function Remove-DetectionRule {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ruleId,

        [Parameter(Mandatory = $false)]
        [string]$token
    )
    $url = "$script:GraphBaseUrl/$ruleId"
    try {
        if ($token) {
            $headers = Get-GraphHeader -token $token
            $null = Invoke-RestMethod -Method DELETE -Uri $url -Headers $headers
        }
        else {
            $null = Invoke-MgGraphRequest -Method DELETE -Uri $url
        }
    }
    catch {
        Write-Host "ERROR: Failed to delete detection rule $ruleId`: $_" -ForegroundColor Red
        throw $_
    }
    Write-Host "Successfully deleted detection rule: $ruleId" -ForegroundColor Green
}

Export-ModuleMember -Function @(
    'Get-GraphAccessToken'
    'Get-GraphHeader'
    'Get-DetectionRules'
    'Get-DetectionRule'
    'New-DetectionRule'
    'Update-DetectionRule'
    'Remove-DetectionRule'
    'Test-ImpactedAsset'
    'Test-ResponseAction'
)
