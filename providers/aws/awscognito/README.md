![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Amazon Providers - Cognito Client

This package is shared between [awsapigwProvider](../awsapigwProvider/README.md) and the [cognitoProvider](../cognitoProvider/README.md). 
It is used to connect to a AWS to obtain data from Cognito services.  

The `awscognito` package provides and implements the following `interface`:

```go
type CognitoClient interface {
	ListUserPools() (apps []policyprovider.ApplicationInfo, err error)
	GetGroups(userPoolId string) (map[string]string, error)
	GetMembersAssignedTo(appInfo policyprovider.ApplicationInfo, groupName string) ([]string, error)
	SetGroupsAssignedTo(groupName string, members []string, applicationInfo policyprovider.ApplicationInfo) error
}
```