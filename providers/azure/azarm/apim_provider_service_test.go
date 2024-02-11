package azarm_test

import (
	"testing"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/models/rar/testsupport/policytestsupport"
	"github.com/hexa-org/policy-mapper/providers/azure/azarm"
	"github.com/hexa-org/policy-mapper/providers/azure/azuretestsupport"
	"github.com/hexa-org/policy-mapper/providers/azure/azuretestsupport/apim_testsupport"
	"github.com/hexa-org/policy-mapper/providers/azure/azuretestsupport/armtestsupport"

	"github.com/stretchr/testify/assert"
)

func TestGetPolicyInfo(t *testing.T) {
	apimApiSvc := apim_testsupport.NewMockArmApimSvc()
	azureClient := azuretestsupport.NewMockAzureClient()
	apimNamedValueSvc := apim_testsupport.NewMockApimNamedValueSvc()

	gatewayUrl := armtestsupport.ApimServiceGatewayUrl
	serviceInfo := apim_testsupport.ApimServiceInfo(gatewayUrl)
	apimApiSvc.ExpectGetApimServiceInfo(serviceInfo)
	apimApiSvc.ExpectGetApimServiceInfo(serviceInfo)
	existingActionRoles := map[string][]string{policytestsupport.ActionGetHrUs: {"some-role"}}
	apimNamedValueSvc.ExpectGetResourceRoles(serviceInfo, existingActionRoles)

	service := azarm.NewApimProviderService(apimApiSvc, azureClient, apimNamedValueSvc)
	appInfo := policyprovider.ApplicationInfo{Service: gatewayUrl}
	_, err := service.GetPolicyInfo(appInfo)
	assert.NoError(t, err)
}

func TestSetPolicyInfo_NoChange(t *testing.T) {
	apimApiSvc := apim_testsupport.NewMockArmApimSvc()
	azureClient := azuretestsupport.NewMockAzureClient()
	apimNamedValueSvc := apim_testsupport.NewMockApimNamedValueSvc()

	gatewayUrl := armtestsupport.ApimServiceGatewayUrl
	serviceInfo := apim_testsupport.ApimServiceInfo(gatewayUrl)
	apimApiSvc.ExpectGetApimServiceInfo(serviceInfo)
	existingActionRoles := map[string][]string{policytestsupport.ActionGetHrUs: {"some-role"}}
	apimNamedValueSvc.ExpectGetResourceRoles(serviceInfo, existingActionRoles)

	newActionRoles := map[string][]string{policytestsupport.ActionGetHrUs: {"some-role"}}
	policies := policytestsupport.MakeRoleSubjectTestPolicies(newActionRoles)
	service := azarm.NewApimProviderService(apimApiSvc, azureClient, apimNamedValueSvc)
	appInfo := policyprovider.ApplicationInfo{Service: gatewayUrl}
	_, err := service.SetPolicyInfo(appInfo, policies)

	assert.NoError(t, err)
}
