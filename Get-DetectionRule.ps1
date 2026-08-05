function Get-DetectionRule {
    param (
        [string]$ruleId,

        [string]$token
    )

    $uri = 'https://graph.microsoft.com/beta/security/rules/detectionRules'
    if ($ruleId) {
        $uri = "$uri/$ruleId"
    }

    if ($token) {
        $result = Invoke-RestMethod -Method GET -Uri $uri -Headers @{
            Authorization = "Bearer $token"
        } -ErrorAction Stop
    }
    else {
        $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    }

    if (-not $ruleId -and $result.value) {
        return $result.value
    }
    return $result
}
