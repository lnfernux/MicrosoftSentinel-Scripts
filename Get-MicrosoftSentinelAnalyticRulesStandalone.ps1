function Parse-MicrosoftSentinelAnalyticRules {
    PARAM(
      $DownloadedRules,
      $prefix,
      $suffix,
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
            # If suffix is defined, match for that
            if($suffix) {
                # Check if both prefix/suffix are defined
                if($prefix) {
                    if($Name.StartsWith($prefix) -and $Name.EndsWith($suffix)) {
                        $DownloadedRule.PSObject.Properties.Remove("id")
                        $DownloadedRule.PSObject.Properties.Remove("etag")
                        $DownloadedRule.properties.PSObject.Properties.Remove("lastModifiedUtc")
                        $DownloadedRule | ConvertTo-Json -Depth 15 | Out-File $outputPath/$File
                    }
                }
                # Only suffix specified
                if($Name.EndsWith($suffix)) {
                    $DownloadedRule.PSObject.Properties.Remove("id")
                    $DownloadedRule.PSObject.Properties.Remove("etag")
                    $DownloadedRule.properties.PSObject.Properties.Remove("lastModifiedUtc")
                    $DownloadedRule | ConvertTo-Json -Depth 15 | Out-File $outputPath/$File
                }
            # Or, if prefix is defined
            } elseif($prefix) {
                if($Name.StartsWith($prefix)) {
                    $DownloadedRule.PSObject.Properties.Remove("id")
                    $DownloadedRule.PSObject.Properties.Remove("etag")
                    $DownloadedRule.properties.PSObject.Properties.Remove("lastModifiedUtc")
                    $DownloadedRule | ConvertTo-Json -Depth 15 | Out-File $outputPath/$File
                }
            # No prefix/suffix, save everything
            } else {
                if($Name) {
                    $DownloadedRule.PSObject.Properties.Remove("id")
                    $DownloadedRule.PSObject.Properties.Remove("etag")
                    $DownloadedRule.properties.PSObject.Properties.Remove("lastModifiedUtc")
                    $DownloadedRule | ConvertTo-Json -Depth 15 | Out-File $outputPath/$File
                }
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
      $prefix,
      $suffix,
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
        Parse-MicrosoftSentinelAnalyticRules -DownloadedRules $DownloadedRules -prefix $prefix -suffix $suffix -outputPath $outputPath

    } catch {
        Write-Host "An error occured in the MicrosoftSentinelAnalyticRules-function: $($_)"
    }
  
}