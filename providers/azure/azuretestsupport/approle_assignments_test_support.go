package azuretestsupport

import (
	"github.com/google/uuid"
	"github.com/hexa-org/policy-mapper/models/rar/testsupport/policytestsupport"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/providers/azure/azad"
	microsoftazure "github.com/hexa-org/policy-mapper/providers/azure/azureProvider"

	"sort"
)

var AppRoleAssignmentGetHrUsAndProfile = []azad.AzureAppRoleAssignment{
	NewAppRoleAssignments(AppRoleIdGetHrUs, policytestsupport.UserIdGetHrUsAndProfile),
	NewAppRoleAssignments(AppRoleIdGetProfile, policytestsupport.UserIdGetHrUsAndProfile),
}

var AppRoleAssignmentGetHrUs = []azad.AzureAppRoleAssignment{
	NewAppRoleAssignments(AppRoleIdGetHrUs, policytestsupport.UserIdGetHrUs),
}

var AppRoleAssignmentGetProfile = []azad.AzureAppRoleAssignment{
	NewAppRoleAssignments(AppRoleIdGetProfile, policytestsupport.UserIdGetProfile),
}

var AppRoleAssignmentMultipleMembers = []azad.AzureAppRoleAssignment{
	NewAppRoleAssignments(AppRoleIdGetHrUs, policytestsupport.UserIdGetHrUs),
	NewAppRoleAssignments(AppRoleIdGetHrUs, policytestsupport.UserIdGetHrUsAndProfile),
}

var AppRoleAssignmentForAdd = []azad.AzureAppRoleAssignment{
	NewAppRoleAssignments(AppRoleIdGetProfile, policytestsupport.UserIdUnassigned1),
	NewAppRoleAssignments(AppRoleIdGetProfile, policytestsupport.UserIdUnassigned2),
}

var AppRoleAssignments = []azad.AzureAppRoleAssignment{
	NewAppRoleAssignments(AppRoleIdGetHrUs, policytestsupport.UserIdGetHrUs),
	NewAppRoleAssignments(AppRoleIdGetProfile, policytestsupport.UserIdGetProfile),
	NewAppRoleAssignments(AppRoleIdGetHrUs, policytestsupport.UserIdGetHrUsAndProfile),
	NewAppRoleAssignments(AppRoleIdGetProfile, policytestsupport.UserIdGetHrUsAndProfile),
}

func NewAppRoleAssignments(appRoleId AppRoleId, principalId string) azad.AzureAppRoleAssignment {
	return azad.AzureAppRoleAssignment{
		ID:          uuid.NewString(),
		AppRoleId:   string(appRoleId),
		PrincipalId: principalId,
		ResourceId:  ServicePrincipalId,
	}
}

func MakeAssignments(assignments []azad.AzureAppRoleAssignment) azad.AzureAppRoleAssignments {
	return azad.AzureAppRoleAssignments{List: assignments}
}

func AssignmentsWithoutId(assignments []azad.AzureAppRoleAssignment) []azad.AzureAppRoleAssignment {
	newAssignments := make([]azad.AzureAppRoleAssignment, 0)
	for _, ara := range assignments {
		newAra := azad.AzureAppRoleAssignment{
			AppRoleId:   ara.AppRoleId,
			PrincipalId: ara.PrincipalId,
			ResourceId:  ara.ResourceId,
		}

		newAssignments = append(newAssignments, newAra)
	}
	return newAssignments
}

func AssignmentsForDelete(assignments []azad.AzureAppRoleAssignment) []azad.AzureAppRoleAssignment {
	newAssignments := make([]azad.AzureAppRoleAssignment, 0)
	for _, ara := range assignments {
		newAra := azad.AzureAppRoleAssignment{
			AppRoleId:  ara.AppRoleId,
			ResourceId: ara.ResourceId,
		}

		newAssignments = append(newAssignments, newAra)
	}
	return newAssignments
}

func MakePolicies(assignments []azad.AzureAppRoleAssignment) []hexapolicy.PolicyInfo {
	policyMapper := microsoftazure.NewAzurePolicyMapper(AzureServicePrincipals(), assignments, policytestsupport.MakePrincipalEmailMap())

	return policyMapper.ToIDQL()
}

func SortAssignments(orig []azad.AzureAppRoleAssignment) []azad.AzureAppRoleAssignment {
	sorted := make([]azad.AzureAppRoleAssignment, 0)
	sorted = append(sorted, orig...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].AppRoleId == sorted[j].AppRoleId {
			return sorted[i].PrincipalId <= sorted[j].PrincipalId
		}

		return sorted[i].AppRoleId < sorted[j].AppRoleId
	})
	return sorted
}
