#requires -Version 7.0

Set-StrictMode -Version Latest

$script:GraphBaseUri = 'https://graph.microsoft.com/v1.0'

function ConvertTo-MdtiBase64Url {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-MdtiCertificateAccessToken {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        '',
        Justification = 'The OAuth response is plaintext and is converted immediately for bearer-token authentication.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $TenantId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $ClientId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CertificateThumbprint,

        [ValidateRange(1, 300)]
        [int] $TimeoutSec = 60
    )

    $certificate = @(
        "Cert:\CurrentUser\My\$CertificateThumbprint"
        "Cert:\LocalMachine\My\$CertificateThumbprint"
    ) |
        Where-Object { Test-Path $_ } |
        Select-Object -First 1 |
        Get-Item

    if (-not $certificate -or -not $certificate.HasPrivateKey) {
        throw "Certificate $CertificateThumbprint with a private key was not found."
    }

    $now = [DateTimeOffset]::UtcNow
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $header = @{
        alg = 'RS256'
        typ = 'JWT'
        x5t = ConvertTo-MdtiBase64Url -Bytes $certificate.GetCertHash()
    } | ConvertTo-Json -Compress
    $payload = @{
        aud = $tokenUri
        exp = $now.AddMinutes(10).ToUnixTimeSeconds()
        iss = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = $now.AddMinutes(-1).ToUnixTimeSeconds()
        sub = $ClientId
    } | ConvertTo-Json -Compress
    $unsignedAssertion = "$(ConvertTo-MdtiBase64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($header))).$(ConvertTo-MdtiBase64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($payload)))"
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)

    try {
        $signature = $rsa.SignData(
            [Text.Encoding]::UTF8.GetBytes($unsignedAssertion),
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
    }
    finally {
        $rsa.Dispose()
    }

    $tokenBody = @{
        client_id             = $ClientId
        client_assertion      = "$unsignedAssertion.$(ConvertTo-MdtiBase64Url -Bytes $signature)"
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        scope                 = 'https://graph.microsoft.com/.default'
        grant_type            = 'client_credentials'
    }

    try {
        $tokenResponse = Invoke-RestMethod `
            -Method Post `
            -Uri $tokenUri `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body $tokenBody `
            -TimeoutSec $TimeoutSec `
            -ErrorAction Stop
    }
    catch {
        throw "Microsoft Graph certificate authentication failed. $($_.Exception.Message)"
    }

    ConvertTo-SecureString $tokenResponse.access_token -AsPlainText -Force
}

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

        $requestUri = if ($All) {
            $response.'@odata.nextLink'
        }
        else {
            $null
        }
    } while ($requestUri)
}

Export-ModuleMember -Function Get-MdtiAccessToken, Get-MdtiCertificateAccessToken, Invoke-MdtiGraphGet