#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $HostValue,

    [SecureString] $AccessToken,

    [ValidateRange(1, 1000)]
    [int] $HistoryTop = 50,

    [switch] $AllHistory,

    [ValidateRange(1, 300)]
    [int] $TimeoutSec = 60
)

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'MdtiGraph.psm1') -Force

$encodedHost = [Uri]::EscapeDataString($HostValue)
$currentRecord = Invoke-MdtiGraphGet `
    -Path "security/threatIntelligence/hosts/$encodedHost/whois" `
    -AccessToken $AccessToken `
    -TimeoutSec $TimeoutSec
$history = @(
    Invoke-MdtiGraphGet `
        -Path "security/threatIntelligence/hosts/$encodedHost/whois/history?`$top=$HistoryTop" `
        -AccessToken $AccessToken `
        -All:$AllHistory `
        -TimeoutSec $TimeoutSec
)

[pscustomobject]@{
    Current = $currentRecord
    History = $history
}