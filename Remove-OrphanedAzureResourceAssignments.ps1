$objectType = "Unknown"
$orphanedIdentities = Get-AzRoleAssignment | Where-object -Property ObjectType -eq $objectType
foreach($identity in $orphanedIdentities= {
  Remove-AzRoleAssignment -ObjectId $identity.ObjectId -RoleDefinitionName $identity.RoleDefinitionName -Scope $identity.Scope
}
