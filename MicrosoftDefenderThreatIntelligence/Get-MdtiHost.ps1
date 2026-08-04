#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $HostValue,

    [SecureString] $AccessToken,

    [ValidateRange(1, 300)]
    [int] $TimeoutSec = 60
)

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'MdtiGraph.psm1') -Force

$encodedHost = [Uri]::EscapeDataString($HostValue)

Invoke-MdtiGraphGet `
    -Path "security/threatIntelligence/hosts/$encodedHost" `
    -AccessToken $AccessToken `
    -TimeoutSec $TimeoutSec