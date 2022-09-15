function Parse-MicrosoftSentinelAnalyticRules {
    PARAM(
      $DownloadedRules,
      $outputPath
    )
    try {
        foreach($DownloadedRule in $DownloadedRules.Value) {
            # Set name variable
            $Name = $DownloadedRule.Properties.DisplayName

            # Remove all spaces and colons from names
            $Name = $Name.Replace(" ", "")
            $Name = $Name.Replace(":", "")    
            $File = "$Name.json"
            if($Name) {
                $DownloadedRule.PSObject.Properties.Remove("id")
                $DownloadedRule.PSObject.Properties.Remove("etag")
                $DownloadedRule.properties.PSObject.Properties.Remove("lastModifiedUtc")
                $DownloadedRule | ConvertTo-Json -Depth 15 | Out-File $outputPath/$File
            }
        } 
    } catch {
      Write-Host "An error occured in the MicrosoftSentinelAnalyticRules-function: $($_)"
    }
}
function Get-MicrosoftSentinelAnalyticRules {
    PARAM(
      $resourceGroup,
      $subscriptionId,
      $outputPath,
      $workspaceName
    )
    try {
        # First, craft the URI for downloading the analytic rules
        $uri = "/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${workspaceName}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-01-01-preview"
        
        # Download all analytic rules
        $DownloadedRules = (Invoke-AzRestMethod -Path $uri).Content | ConvertFrom-Json -Depth 15

        # Check that outputPath exists, if not create
        If(!(Test-Path $outputPath)) {
            New-Item -ItemType Directory -Path $outputPath
        }
        Parse-MicrosoftSentinelAnalyticRules -DownloadedRules $DownloadedRules -outputPath $outputPath

    } catch {
        Write-Host "An error occured in the MicrosoftSentinelAnalyticRules-function: $($_)"
    }
}