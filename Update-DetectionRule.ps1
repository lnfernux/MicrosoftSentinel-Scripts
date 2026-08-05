function Update-DetectionRule {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ruleId,

        [string]$description,

        [ValidateSet('enabled', 'disabled')]
        [string]$status,

        [ValidatePattern('^P')]
        [string]$frequency,

        [string]$token
    )

    $body = @{}
    if ($PSBoundParameters.ContainsKey('description')) {
        $body.description = $description
    }
    if ($PSBoundParameters.ContainsKey('status')) {
        $body.status = $status
    }
    if ($PSBoundParameters.ContainsKey('frequency')) {
        $body.schedule = @{ frequency = $frequency }
    }
    if (-not $body.Count) {
        throw 'Supply description, status, or frequency.'
    }

    $request = @{
        Method = 'PATCH'
        Uri = "https://graph.microsoft.com/beta/security/rules/detectionRules/$ruleId"
        Body = $body | ConvertTo-Json -Depth 5
        Headers = @{ 'Content-Type' = 'application/json' }
        ErrorAction = 'Stop'
    }
    if ($token) {
        $request.Headers.Authorization = "Bearer $token"
        return Invoke-RestMethod @request
    }
    return Invoke-MgGraphRequest @request
}
