#requires -Version 7.0

[CmdletBinding()]
param(
    [SecureString] $AccessToken,

    [ValidateRange(1, 1000)]
    [int] $Top = 50,

    [switch] $All,

    [ValidateRange(1, 300)]
    [int] $TimeoutSec = 60
)

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'MdtiGraph.psm1') -Force

Invoke-MdtiGraphGet `
    -Path "security/threatIntelligence/intelProfiles?`$top=$Top" `
    -AccessToken $AccessToken `
    -All:$All `
    -TimeoutSec $TimeoutSec