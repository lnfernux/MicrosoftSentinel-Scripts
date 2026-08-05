function New-DetectionRule {
    param (
        [Parameter(Mandatory = $true)]
        [string]$id,

        [Parameter(Mandatory = $true)]
        [string]$displayName,

        [Parameter(Mandatory = $true)]
        [string]$description,

        [Parameter(Mandatory = $true)]
        [string]$queryText,

        [ValidatePattern('^P')]
        [string]$frequency = 'PT1H',

        [ValidateSet('informational', 'low', 'medium', 'high')]
        [string]$severity = 'informational',

        [string]$deviceIdColumn = 'DeviceId',

        [string]$deviceNameColumn = 'DeviceName',

        [string]$tactic = 'Execution',

        [string[]]$techniques = @(),

        [hashtable]$customDetails,

        [string]$token
    )

    $techniqueMappings = @($techniques | ForEach-Object { @{ technique = $_ } })
    $body = @{
        '@odata.type' = '#microsoft.graph.security.detectionRule'
        id = $id
        displayName = $displayName
        description = $description
        status = 'disabled'
        queryCondition = @{ queryText = $queryText }
        schedule = @{ frequency = $frequency }
        detectionAction = @{
            alertTemplate = @{
                title = $displayName
                description = $description
                severity = $severity
                entityMappings = @{
                    hosts = @(
                        @{
                            deviceIdColumn = $deviceIdColumn
                            nameColumn = $deviceNameColumn
                        }
                    )
                }
                tactics = @(
                    @{
                        tactic = $tactic
                        techniques = $techniqueMappings
                    }
                )
            }
        }
    }
    if ($customDetails) {
        $body.detectionAction.alertTemplate.customDetails = $customDetails
    }

    $request = @{
        Method = 'POST'
        Uri = 'https://graph.microsoft.com/beta/security/rules/detectionRules'
        Body = $body | ConvertTo-Json -Depth 10
        Headers = @{ 'Content-Type' = 'application/json' }
        ErrorAction = 'Stop'
    }
    if ($token) {
        $request.Headers.Authorization = "Bearer $token"
        return Invoke-RestMethod @request
    }
    return Invoke-MgGraphRequest @request
}
