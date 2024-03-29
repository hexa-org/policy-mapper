package azuretestsupport

import (
	"encoding/json"
	"fmt"

	"github.com/hexa-org/policy-mapper/models/rar/testsupport/policytestsupport"
	"github.com/hexa-org/policy-mapper/providers/azure/azad"
)

const ServicePrincipalId = "some-service-principal-id"

type AppRoleId string

const AppRoleIdGetHrUs AppRoleId = "app-role-get-hr-us"
const AppRoleIdGetProfile AppRoleId = "app-role-get-profile"

var ServicePrincipalsRespJson = fmt.Sprintf(`{"value": [
{
	"id": "%s",
	"displayName": "%s",
	"appRoles": [
		{
			"allowedMemberTypes": [
				"User"
			],
			"description": "Allows GET to the /humanresources/us",
			"displayName": "GetHR-US",
			"id": "%s",
			"isEnabled": true,
			"origin": "Application",
			"value": "%s"
		},
		{
			"allowedMemberTypes": [
				"User"
			],
			"description": "Allows GET to the /profile",
			"displayName": "AppRoleIdGetProfile",
			"id": "%s",
			"isEnabled": true,
			"origin": "Application",
			"value": "%s"
		}
	] 
}]}`, ServicePrincipalId, policytestsupport.PolicyObjectResourceId, AppRoleIdGetHrUs, policytestsupport.ActionGetHrUs, AppRoleIdGetProfile, policytestsupport.ActionGetProfile)

func AzureServicePrincipals() azad.AzureServicePrincipals {
	var sps azad.AzureServicePrincipals
	_ = json.Unmarshal([]byte(ServicePrincipalsRespJson), &sps)
	return sps
}
