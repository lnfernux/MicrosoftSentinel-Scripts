function New-DetectionRule {
  param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$displayName,

    [Parameter(Mandatory = $true)]
    [bool]$isEnabled,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$queryText,

    [Parameter(Mandatory = $true)]
    [ValidateSet("0","1H", "3H", "12H", "24H")]
    [string]$period,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$alertTitle,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$alertDescription,

    [Parameter(Mandatory = $true)]
    [ValidateSet("informational", "low", "medium", "high")]
    [string]$severity,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Malware","Execution", "Discovery", "Lateral Movement", "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Collection", "Exfiltration", "CommandAndControl", "SuspiciousActivity", "Unwanted Software", "Ransomware", "Exploit", "Impact")]
    [string]$category,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$identifier,

    [string[]]$mitreTechniques = @(),

    $recommendedActions = $null,

    [ValidateSet("full", "selective")]
    [string]$isolationType,

    [Parameter(Mandatory = $false)]
    [string]$token
  )

  $body = @{
    displayName = $displayName
    isEnabled = $isEnabled
    queryCondition = @{
      queryText = $queryText
    }
    schedule = @{
      period = $period
    }
    detectionAction = @{
      alertTemplate = @{
        title = $alertTitle
        description = $alertDescription
        severity = $severity.ToLower()
        category = $category
        recommendedActions = $recommendedActions
        mitreTechniques = $mitreTechniques
        impactedAssets = @(
          @{
            '@odata.type' = '#microsoft.graph.security.impactedDeviceAsset'
            identifier    = $identifier
          }
        )
      }
      organizationalScope = $null
      responseActions = @(
      )
    }
  }
  if($isolationType) {
    $body.detectionAction.responseActions += @{
      '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'
      identifier    = $identifier
      isolationType = $isolationType
    }
  }
  $jsonBody = $body | ConvertTo-Json -Depth 10
  if($token) {
    Write-Host "Using provided access token for authentication."
    $Headers = @{
      "Authorization" = "Bearer $token"
      "Content-Type" = "application/json"
    }
      $return = Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules" -Body $jsonBody -Headers $Headers
  } else {
    $Headers = @{"Content-Type" = "application/json"}
    $return = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules" -Body $jsonBody -Headers $Headers
  }
  if(!$return) {Write-Host "Failed to create detection rule or an error occurred."
    return $jsonBody
  }
  return $return
}
