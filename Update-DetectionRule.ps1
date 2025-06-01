function Update-DetectionRule {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ruleId,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$displayName,

    [Parameter(Mandatory = $false)]
    [bool]$isEnabled,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$queryText,

    [Parameter(Mandatory = $false)]
    [ValidateSet("0","1H", "3H", "12H", "24H")]
    [string]$period,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$alertTitle,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$alertDescription,

    [Parameter(Mandatory = $false)]
    [ValidateSet("informational", "low", "medium", "high")]
    [string]$severity,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Malware","Execution", "Discovery", "Lateral Movement", "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Collection", "Exfiltration", "CommandAndControl", "SuspiciousActivity", "Unwanted Software", "Ransomware", "Exploit")]
    [string]$category,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$identifier,

    [string[]]$mitreTechniques = @(),

    $recommendedActions = $null,

    [ValidateSet("full", "selective")]
    [string]$isolationType,

    [Parameter(Mandatory = $false)]
    [string]$token
  )

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

  $detectionAction = @{}
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
      $detectionAction.alertTemplate = $alertTemplate
  }
  $detectionAction.organizationalScope = $null

  $detectionAction.responseActions = @()
  if ($PSBoundParameters.ContainsKey('isolationType') -and $PSBoundParameters.ContainsKey('identifier')) {
      $detectionAction.responseActions += @{
          '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'
          identifier    = $identifier
          isolationType = $isolationType
      }
  }

  if ($detectionAction.Count -gt 0) {
      $body.detectionAction = $detectionAction
  }
  $jsonBody = $body | ConvertTo-Json -Depth 10
  if($token) {
    Write-Host "Using provided access token for authentication."
    $Headers = @{
      "Authorization" = "Bearer $token" 
      "Content-Type" = "application/json"
    }
    $return = Invoke-RestMethod -Method PATCH -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules/$ruleId" -Body $jsonBody -Headers $Headers
  } else {
    $Headers = @{"Content-Type" = "application/json"}
    $return = Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules/$ruleId" -Body $jsonBody -Headers @{"Content-Type" = "application/json"}
  }
  if(!$return) {
    Write-Host "Failed to update detection rule or an error occurred."
    return $body
  }
  Write-Host "Detection rule updated successfully."
  return $return
}
