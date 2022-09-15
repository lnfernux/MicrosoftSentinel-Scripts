$SecuredPassword = $Password | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecuredPassword
Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $Credential
$params = @{
    existingWorkspaceName = "infernux-security-permissionstest-law"
    automationRuleName = "AR-PermissionsTest"
    existingRuleId = "analytic-rule-guid"
    playbookResourceId = "/subscriptions/subscriptionid/resourceGroups/infernux-security/providers/Microsoft.Logic/workflows/infernux-test1"
    tenantId = "tenantId"
}
New-AzResourceGroupDeployment -ResourceGroupName $resourceGroup -TemplateFile .\MicrosoftSentinel-Templates\AutomationRules\PermissionsTest.json -TemplateParameterObject $param