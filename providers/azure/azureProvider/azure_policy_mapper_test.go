package azureProvider_test

import (
	"github.com/hexa-org/policy-mapper/models/rar/testsupport/policytestsupport"
	"github.com/hexa-org/policy-mapper/providers/azure/azad"
	"github.com/hexa-org/policy-mapper/providers/azure/azureProvider"
	"github.com/hexa-org/policy-mapper/providers/azure/azuretestsupport"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestAzurePolicyMapper_ToIDQL(t *testing.T) {
	principalEmails := policytestsupport.MakePrincipalEmailMap()
	roleAssignments := azuretestsupport.AppRoleAssignments
	sps := azuretestsupport.AzureServicePrincipals()
	mapper := azureProvider.NewAzurePolicyMapper(sps, roleAssignments, principalEmails)
	actPolicies := mapper.ToIDQL()
	assert.NotNil(t, actPolicies)
	assert.Equal(t, len(sps.List[0].AppRoles), len(actPolicies))

	actActionMembersMap := make(map[string][]string)
	for _, pol := range actPolicies {
		assert.Equal(t, 1, len(pol.Actions))
		assert.Equal(t, sps.List[0].Name, pol.Object.ResourceID)
		actActionMembersMap[pol.Actions[0].ActionUri] = pol.Subject.Members
	}

	for _, expAction := range []string{policytestsupport.ActionGetHrUs, policytestsupport.ActionGetProfile} {

		assert.NotNil(t, actActionMembersMap[expAction])
		var mainEmail string
		switch expAction {
		case policytestsupport.ActionGetHrUs:
			mainEmail = policytestsupport.UserEmailGetHrUs
			break
		case policytestsupport.ActionGetProfile:
			mainEmail = policytestsupport.UserEmailGetProfile
		}
		assert.Contains(t, actActionMembersMap[expAction], "user:"+mainEmail)
		assert.Contains(t, actActionMembersMap[expAction], "user:"+policytestsupport.UserEmailGetHrUsAndProfile)
	}
}

func TestAzurePolicyMapper_ToIDQL_NoRoleAssignments(t *testing.T) {
	sps := azuretestsupport.AzureServicePrincipals()
	mapper := azureProvider.NewAzurePolicyMapper(sps, nil, nil)
	actPolicies := mapper.ToIDQL()
	assert.NotNil(t, actPolicies)
	assert.Equal(t, len(sps.List[0].AppRoles), len(actPolicies))

	actPolicyActionMap := make(map[string]bool)
	log.Println(actPolicies)
	for _, pol := range actPolicies {
		assert.Equal(t, 1, len(pol.Actions))
		assert.Equal(t, sps.List[0].Name, pol.Object.ResourceID)
		assert.NotNil(t, pol.Subject.Members)
		assert.Empty(t, pol.Subject.Members)
		actPolicyActionMap[pol.Actions[0].ActionUri] = true
	}

	for _, expAction := range []string{policytestsupport.ActionGetHrUs, policytestsupport.ActionGetProfile} {
		assert.True(t, actPolicyActionMap[expAction])
	}
}

func TestAzurePolicyMapper_ToIDQL_NoAppRoles(t *testing.T) {
	mapper := azureProvider.NewAzurePolicyMapper(azad.AzureServicePrincipals{}, nil, nil)
	actPolicies := mapper.ToIDQL()
	assert.NotNil(t, actPolicies)
	assert.Equal(t, 0, len(actPolicies))
}
