#requires -Version 7.0

Set-StrictMode -Version Latest

$script:GraphBaseUri = 'https://graph.microsoft.com/v1.0'

function Get-MdtiAccessToken {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        '',
        Justification = 'The OAuth response is plaintext and is converted immediately for bearer-token authentication.'
    )]
    [CmdletBinding()]
    param(
        [SecureString] $AccessToken,

        [ValidateRange(1, 300)]
        [int] $TimeoutSec = 60
    )

    if ($AccessToken) {
        return $AccessToken
    }

    $requiredVariables = @(
        'MDTI_TENANT_ID'
        'MDTI_CLIENT_ID'
        'MDTI_CLIENT_SECRET'
    )

    foreach ($variableName in $requiredVariables) {
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($variableName))) {
            throw "Environment variable $variableName is not set."
        }
    }

    $tokenBody = @{
        client_id     = $env:MDTI_CLIENT_ID
        client_secret = $env:MDTI_CLIENT_SECRET
        scope         = 'https://graph.microsoft.com/.default'
        grant_type    = 'client_credentials'
    }

    try {
        $tokenResponse = Invoke-RestMethod `
            -Method Post `
            -Uri "https://login.microsoftonline.com/$($env:MDTI_TENANT_ID)/oauth2/v2.0/token" `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body $tokenBody `
            -TimeoutSec $TimeoutSec `
            -ErrorAction Stop
    }
    catch {
        throw "Microsoft Graph authentication failed. $($_.Exception.Message)"
    }

    ConvertTo-SecureString $tokenResponse.access_token -AsPlainText -Force
}

function Invoke-MdtiGraphGet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [SecureString] $AccessToken,

        [switch] $All,

        [ValidateRange(1, 300)]
        [int] $TimeoutSec = 60
    )

    $resolvedToken = Get-MdtiAccessToken -AccessToken $AccessToken -TimeoutSec $TimeoutSec
    $requestUri = if ($Path -match '^https://') {
        $Path
    }
    else {
        "$script:GraphBaseUri/$($Path.TrimStart('/'))"
    }

    do {
        try {
            $response = Invoke-RestMethod `
                -Method Get `
                -Uri $requestUri `
                -Authentication Bearer `
                -Token $resolvedToken `
                -Headers @{ Accept = 'application/json' } `
                -TimeoutSec $TimeoutSec `
                -ErrorAction Stop
        }
        catch {
            $requestError = $_
            $statusCode = if ($requestError.Exception.Response) {
                [int] $requestError.Exception.Response.StatusCode
            }
            else {
                $null
            }
            $graphMessage = $requestError.Exception.Message

            if ($requestError.ErrorDetails -and
                -not [string]::IsNullOrWhiteSpace($requestError.ErrorDetails.Message)) {
                try {
                    $graphError = $requestError.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
                    $graphMessage = $graphError.error.message
                }
                catch {
                    $graphMessage = $requestError.ErrorDetails.Message
                }
            }

            if ($statusCode) {
                throw "Microsoft Graph request failed with HTTP $statusCode. $graphMessage"
            }

            throw "Microsoft Graph request failed. $graphMessage"
        }

        if ($response.PSObject.Properties.Name -contains 'value') {
            $response.value
        }
        else {
            $response
        }

        $requestUri = if ($All -and
            $response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $response.'@odata.nextLink'
        }
        else {
            $null
        }
    } while ($requestUri)
}

Export-ModuleMember -Function Get-MdtiAccessToken, Invoke-MdtiGraphGet
