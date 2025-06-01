function Get-DetectionRule {
  param (
    [Parameter(Mandatory = $false)]
    [string]$token,
    [Parameter(Mandatory = $false)]
    [string]$ruleId
  )
  # If specific rule id, get only one rule - if not default to all
  if($ruleId) {
    if ($token) {
        $headers = @{
            "Authorization" = "Bearer $token"
            "Content-Type" = "application/json"
        }        
        $result = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules/$ruleId" -Header $headers
    } else {
        $result =  Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules/$ruleId"
    }
  } else {
    if ($token) {
        $headers = @{
          "Authorization" = "Bearer $token"
          "Content-Type" = "application/json"
          }
        $result = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules" -Header $headers
    } else {
        $result =  Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules"
    }
  }
  if(!$result) {
    Write-Host "No detection rules found or an error occurred."
    return $null
  }
  return $result 
}
