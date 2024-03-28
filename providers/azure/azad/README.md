![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Azure - Graph Client Package

This package is used by the azureProvider to make calls to the Azure Graph API.

It implements the following interface:

```go
type AzureClient interface {
	GetAzureApplications(key []byte) ([]AzureWebApp, error)
	GetWebApplications(key []byte) ([]policyprovider.ApplicationInfo, error)
	GetServicePrincipals(key []byte, appId string) (AzureServicePrincipals, error)
	GetUserInfoFromPrincipalId(key []byte, principalId string) (AzureUser, error)
	GetPrincipalIdFromEmail(key []byte, email string) (string, error)
	GetAppRoleAssignedTo(key []byte, servicePrincipalId string) (AzureAppRoleAssignments, error)
	SetAppRoleAssignedTo(key []byte, servicePrincipalId string, assignments []AzureAppRoleAssignment) error
}
```