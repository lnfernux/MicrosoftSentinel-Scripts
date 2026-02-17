$script:GraphBaseUrl = "https://graph.microsoft.com/beta/security/rules/detectionRules"

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

function New-DetectionRule {
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
        [ValidateSet("0", "1H", "3H", "12H", "24H")]
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
        [ValidateSet("Malware", "Execution", "Discovery", "Lateral Movement", "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Collection", "Exfiltration", "CommandAndControl", "SuspiciousActivity", "Unwanted Software", "Ransomware", "Exploit", "Impact")]
        [string]$category,

        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()]
        [string]$identifier,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [string[]]$mitreTechniques,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        $recommendedActions,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateSet("full", "selective")]
        [string]$isolationType,

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

    $body = @{
        displayName    = $displayName
        isEnabled      = $isEnabled
        queryCondition = @{
            queryText = $queryText
        }
        schedule = @{
            period = $period
        }
        detectionAction = @{
            alertTemplate = @{
                title          = $alertTitle
                description    = $alertDescription
                severity       = $severity.ToLower()
                category       = $category
                impactedAssets = @(
                    @{
                        '@odata.type' = '#microsoft.graph.security.impactedDeviceAsset'
                        identifier    = $identifier
                    }
                )
            }
            organizationalScope = $null
            responseActions     = @()
        }
    }

    if ($PSBoundParameters.ContainsKey('mitreTechniques') -and $mitreTechniques.Count -gt 0) {
        $body.detectionAction.alertTemplate.mitreTechniques = $mitreTechniques
    }
    if ($PSBoundParameters.ContainsKey('recommendedActions') -and $recommendedActions) {
        $body.detectionAction.alertTemplate.recommendedActions = $recommendedActions
    }
    if ($isolationType) {
        $body.detectionAction.responseActions += @{
            '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'
            identifier    = $identifier
            isolationType = $isolationType
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
        Write-Host "ERROR: Failed to create detection rule: $_" -ForegroundColor Red
        throw $_
    }
    Write-Host "Successfully created detection rule: $displayName" -ForegroundColor Green
    return $result
}

function Update-DetectionRule {
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
        [ValidateSet("0", "1H", "3H", "12H", "24H")]
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
        [ValidateSet("Malware", "Execution", "Discovery", "Lateral Movement", "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Collection", "Exfiltration", "CommandAndControl", "SuspiciousActivity", "Unwanted Software", "Ransomware", "Exploit", "Impact")]
        [string]$category,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateNotNullOrEmpty()]
        [string]$identifier,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [string[]]$mitreTechniques,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        $recommendedActions,

        [Parameter(Mandatory = $false, ParameterSetName = 'Parameters')]
        [ValidateSet("full", "selective")]
        [string]$isolationType,

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
        $body.schedule = @{ period = $period }
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
    if ($PSBoundParameters.ContainsKey('identifier')) {
        $alertTemplate.impactedAssets = @(
            @{
                '@odata.type' = '#microsoft.graph.security.impactedDeviceAsset'
                identifier    = $identifier
            }
        )
    }

    if ($alertTemplate.Count -gt 0) {
        $detectionAction = @{ alertTemplate = $alertTemplate }
        if ($PSBoundParameters.ContainsKey('isolationType') -and $PSBoundParameters.ContainsKey('identifier')) {
            $detectionAction.responseActions = @(
                @{
                    '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'
                    identifier    = $identifier
                    isolationType = $isolationType
                }
            )
        }
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
)
