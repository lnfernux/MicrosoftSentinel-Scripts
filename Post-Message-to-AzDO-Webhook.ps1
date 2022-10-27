Param
(
    # URL to the Azure DevOps incoming webhook endpoint. Expected format is 
    # https://dev.azure.com/<org>/_apis/public/distributedtask/webhooks/<svc-trig>/?api-version=6.0-preview. 
    [uri]
    $Url,

    # Shared secret used to sign the JSON payload. Must be the same value supplied during 
    # the creation of the Incoming Webhook service connection
    [string]
    $Secret,

    # HTTP header name to send the hash signature. When omitted, defaults to "X-Hub-Signature"
    [string]
    $HeaderName = 'X-Hub-Signature',

    # JSON payload to send to the Azure DevOps web hook
    [string]
    $Body 
)

$hmacSha = New-Object System.Security.Cryptography.HMACSHA1 -Property @{
    Key = [Text.Encoding]::ASCII.GetBytes($secret)
}

$hashBytes = $hmacSha.ComputeHash([Text.Encoding]::UTF8.GetBytes($body))
$signature = ''

$hashBytes | ForEach-Object { $signature += $_.ToString('x2')}

$headers = @{
    $headerName = "sha1=$signature"
}

Invoke-WebRequest -Uri $Url -Body $Body -Method Post -ContentType 'application/json' -Headers $headers
