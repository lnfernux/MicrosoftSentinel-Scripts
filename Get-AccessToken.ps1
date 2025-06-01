function Get-AccessToken {
  param( 
    [Parameter(Mandatory = $true)]
    [string]$tenantId,

    [Parameter(Mandatory = $true)]
    [string]$clientId,

    [Parameter(Mandatory = $true)]
    [string]$clientSecret
  )
  $global:token = ""
  $graphResource = 'https://graph.microsoft.com/'
  $oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"
  $authBody = [Ordered]@{
      resource      = $graphResource
      client_id     = $clientId
      client_secret = $clientSecret
      grant_type    = 'client_credentials'
  }

  Write-Host "[A] Authenticating to tenant's $TenantId Graph API"
  try {
      $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
      $token = $authResponse.access_token
  } catch {
      Write-Host -ForegroundColor Red "[!] Authentication failed: $_"
      exit 1
  }
  Write-Host "[*] Authentication successful"
  Write-Host "[*] Access token obtained successfully"
  return $token
}
