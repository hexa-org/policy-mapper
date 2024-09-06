package azureProvider_test

import (
    "log"
    "net/http"
    "testing"

    "github.com/hexa-org/policy-mapper/api/policyprovider"
    "github.com/hexa-org/policy-mapper/models/rar/testsupport/policytestsupport"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
    "github.com/hexa-org/policy-mapper/providers/azure/azad"
    "github.com/hexa-org/policy-mapper/providers/azure/azureProvider"
    "github.com/hexa-org/policy-mapper/providers/azure/azuretestsupport"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

func TestDiscoverApplications(t *testing.T) {
    key := azuretestsupport.AzureKeyBytes()
    mockAzClient := azuretestsupport.NewMockAzureClient()
    expApps := []policyprovider.ApplicationInfo{
        {
            ObjectID:    "anId",
            Name:        "aName",
            Description: "aDescription",
            Service:     "App Service",
        },
    }
    mockAzClient.On("GetWebApplications", key).Return(expApps, nil)

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))

    info := policyprovider.IntegrationInfo{Name: "azure", Key: key}
    applications, _ := p.DiscoverApplications(info)
    log.Println(applications[0])

    assert.Len(t, applications, 1)
    assert.Equal(t, "azure", p.Name())
    assert.Equal(t, "App Service", applications[0].Service)
    mockAzClient.AssertExpectations(t)
}

func TestGetPolicy_WithoutUserEmail(t *testing.T) {
    appId := azuretestsupport.AzureAppId
    key := azuretestsupport.AzureKeyBytes()

    mockAzClient := azuretestsupport.NewMockAzureClient()
    mockAzClient.ExpectGetServicePrincipals()
    mockAzClient.ExpectAppRoleAssignedTo(azuretestsupport.AppRoleAssignmentGetProfile)
    mockAzClient.On("GetUserInfoFromPrincipalId", mock.Anything, mock.Anything).
        Return(azad.AzureUser{
            PrincipalId: policytestsupport.UserIdGetProfile,
        }, nil)

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))

    info := policyprovider.IntegrationInfo{Name: "azure", Key: key}
    appInfo := policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: appId}

    actualPolicies, err := p.GetPolicyInfo(info, appInfo)
    assert.NoError(t, err)
    assert.NotNil(t, actualPolicies)
    assert.Equal(t, len(azuretestsupport.AzureServicePrincipals().List[0].AppRoles), len(actualPolicies))

    for _, pol := range actualPolicies {
        assert.True(t, len(pol.Actions) > 0)
        assert.NotEmpty(t, pol.Actions[0].ActionUri)
        assert.Equal(t, 0, len(pol.Subjects))
        assert.Equal(t, policytestsupport.PolicyObjectResourceId, pol.Object.ResourceID)
    }
    mockAzClient.AssertExpectations(t)
}

func TestGetPolicy_WithRoleAssignment(t *testing.T) {
    appId := azuretestsupport.AzureAppId
    key := azuretestsupport.AzureKeyBytes()
    expAssignments := azuretestsupport.AppRoleAssignmentGetHrUs

    mockAzClient := azuretestsupport.NewMockAzureClient()
    mockAzClient.ExpectGetServicePrincipals()
    mockAzClient.ExpectAppRoleAssignedTo(expAssignments)
    mockAzClient.ExpectGetUserInfoFromPrincipalId(policytestsupport.UserIdGetHrUs)

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))

    info := policyprovider.IntegrationInfo{Name: "azure", Key: key}
    appInfo := policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: appId}

    actualPolicies, err := p.GetPolicyInfo(info, appInfo)
    assert.NoError(t, err)
    assert.NotNil(t, actualPolicies)
    assert.Equal(t, len(azuretestsupport.AzureServicePrincipals().List[0].AppRoles), len(actualPolicies))

    expPolicies := azuretestsupport.MakePolicies(expAssignments)
    assert.Equal(t, len(expPolicies), len(actualPolicies))
    assert.True(t, policytestsupport.ContainsPolicies(t, expPolicies, actualPolicies))
    mockAzClient.AssertExpectations(t)
}

func TestGetPolicy_MultiplePolicies(t *testing.T) {
    appId := azuretestsupport.AzureAppId
    key := azuretestsupport.AzureKeyBytes()
    expAssignments := azuretestsupport.AppRoleAssignmentGetHrUsAndProfile

    mockAzClient := azuretestsupport.NewMockAzureClient()
    mockAzClient.ExpectGetServicePrincipals()
    mockAzClient.ExpectAppRoleAssignedTo(expAssignments)
    mockAzClient.ExpectGetUserInfoFromPrincipalId(policytestsupport.UserIdGetHrUsAndProfile)

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))

    info := policyprovider.IntegrationInfo{Name: "azure", Key: key}
    appInfo := policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: appId}

    actualPolicies, err := p.GetPolicyInfo(info, appInfo)
    assert.NoError(t, err)
    assert.NotNil(t, actualPolicies)
    assert.Equal(t, len(azuretestsupport.AzureServicePrincipals().List[0].AppRoles), len(actualPolicies))

    expPolicies := azuretestsupport.MakePolicies(expAssignments)
    assert.Equal(t, len(expPolicies), len(actualPolicies))
    assert.True(t, policytestsupport.ContainsPolicies(t, expPolicies, actualPolicies))
    mockAzClient.AssertExpectations(t)
}

func TestGetPolicy_MultipleMembersInOnePolicy(t *testing.T) {
    appId := azuretestsupport.AzureAppId
    key := azuretestsupport.AzureKeyBytes()
    expAssignments := azuretestsupport.AppRoleAssignmentMultipleMembers

    mockAzClient := azuretestsupport.NewMockAzureClient()
    mockAzClient.ExpectGetServicePrincipals()
    mockAzClient.ExpectAppRoleAssignedTo(expAssignments)
    mockAzClient.ExpectGetUserInfoFromPrincipalId(policytestsupport.UserIdGetHrUs, policytestsupport.UserIdGetHrUsAndProfile)

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))

    info := policyprovider.IntegrationInfo{Name: "azure", Key: key}
    appInfo := policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: appId}

    actualPolicies, err := p.GetPolicyInfo(info, appInfo)
    assert.NoError(t, err)
    assert.NotNil(t, actualPolicies)
    assert.Equal(t, len(azuretestsupport.AzureServicePrincipals().List[0].AppRoles), len(actualPolicies))

    expPolicies := azuretestsupport.MakePolicies(expAssignments)
    assert.Equal(t, len(expPolicies), len(actualPolicies))
    assert.True(t, policytestsupport.ContainsPolicies(t, expPolicies, actualPolicies))
    mockAzClient.AssertExpectations(t)
}

func TestSetPolicy_withInvalidArguments(t *testing.T) {
    azureProvider := azureProvider.NewAzureProvider()
    key := []byte("key")

    status, err := azureProvider.SetPolicyInfo(
        policyprovider.IntegrationInfo{Name: "azure", Key: key},
        policyprovider.ApplicationInfo{Name: "anAppName", Description: "anAppId"},
        []hexapolicy.PolicyInfo{{
            Meta:     hexapolicy.MetaInfo{Version: "0"},
            Actions:  []hexapolicy.ActionInfo{{"azure:anAppRoleId"}},
            Subjects: []string{"aPrincipalId:aPrincipalDisplayName", "yetAnotherPrincipalId:yetAnotherPrincipalDisplayName", "andAnotherPrincipalId:andAnotherPrincipalDisplayName"},
            Object: hexapolicy.ObjectInfo{
                ResourceID: "anObjectId",
            },
        }})

    assert.Equal(t, http.StatusInternalServerError, status)
    assert.EqualError(t, err, "Key: 'ApplicationInfo.ObjectID' Error:Field validation for 'ObjectID' failed on the 'required' tag")

    status, err = azureProvider.SetPolicyInfo(
        policyprovider.IntegrationInfo{Name: "azure", Key: key},
        policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: "aDescription"},
        []hexapolicy.PolicyInfo{{
            Meta:     hexapolicy.MetaInfo{Version: "0"},
            Actions:  []hexapolicy.ActionInfo{{"azure:anAppRoleId"}},
            Subjects: []string{"aPrincipalId:aPrincipalDisplayName", "yetAnotherPrincipalId:yetAnotherPrincipalDisplayName", "andAnotherPrincipalId:andAnotherPrincipalDisplayName"},
            Object:   hexapolicy.ObjectInfo{},
        }})

    assert.Equal(t, http.StatusInternalServerError, status)
    assert.EqualError(t, err, "Key: '[0].Object.ResourceID' Error:Field validation for 'ResourceID' failed on the 'required' tag")
}

func TestSetPolicy_IgnoresAllPrincipalIdsNotFound(t *testing.T) {
    appId := azuretestsupport.AzureAppId
    key := azuretestsupport.AzureKeyBytes()

    mockAzClient := azuretestsupport.NewMockAzureClient()
    mockAzClient.ExpectGetServicePrincipals()

    mockAzClient.ExpectGetPrincipalIdFromEmail(policytestsupport.UserEmailGetHrUs, "")
    mockAzClient.ExpectGetPrincipalIdFromEmail(policytestsupport.UserEmailGetProfile, "")

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))
    status, err := p.SetPolicyInfo(
        policyprovider.IntegrationInfo{Name: "azure", Key: key},
        policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: appId},
        []hexapolicy.PolicyInfo{{
            Meta:    hexapolicy.MetaInfo{Version: "0"},
            Actions: []hexapolicy.ActionInfo{{"azure:" + policytestsupport.ActionGetHrUs}},
            Subjects: []string{"user:" + policytestsupport.UserEmailGetHrUs,
                "user:" + policytestsupport.UserEmailGetProfile},
            Object: hexapolicy.ObjectInfo{
                ResourceID: policytestsupport.PolicyObjectResourceId,
            },
        }})

    assert.NoError(t, err)
    assert.Equal(t, http.StatusCreated, status)
    mockAzClient.AssertExpectations(t)
}

func TestSetPolicy_IgnoresAnyNotFoundPrincipalId(t *testing.T) {
    appId := azuretestsupport.AzureAppId
    key := azuretestsupport.AzureKeyBytes()

    mockAzClient := azuretestsupport.NewMockAzureClient()
    mockAzClient.ExpectGetServicePrincipals()

    mockAzClient.ExpectGetPrincipalIdFromEmail(policytestsupport.UserEmailGetHrUs, policytestsupport.UserIdGetHrUs)
    mockAzClient.ExpectGetPrincipalIdFromEmail(policytestsupport.UserEmailGetProfile, "")
    mockAzClient.ExpectSetAppRoleAssignedTo(azuretestsupport.AppRoleAssignmentGetHrUs)

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))
    status, err := p.SetPolicyInfo(
        policyprovider.IntegrationInfo{Name: "azure", Key: key},
        policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: appId},
        []hexapolicy.PolicyInfo{{
            Meta:    hexapolicy.MetaInfo{Version: "0"},
            Actions: []hexapolicy.ActionInfo{{"azure:" + policytestsupport.ActionGetHrUs}},
            Subjects: []string{"user:" + policytestsupport.UserEmailGetHrUs,
                "user:" + policytestsupport.UserEmailGetProfile},
            Object: hexapolicy.ObjectInfo{
                ResourceID: policytestsupport.PolicyObjectResourceId,
            },
        }})

    assert.NoError(t, err)
    assert.Equal(t, http.StatusCreated, status)
    mockAzClient.AssertExpectations(t)
}

func TestSetPolicy_AddAssignment_IgnoresInvalidAction(t *testing.T) {
    appId := azuretestsupport.AzureAppId
    key := azuretestsupport.AzureKeyBytes()

    mockAzClient := azuretestsupport.NewMockAzureClient()
    mockAzClient.ExpectGetServicePrincipals()

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))
    status, err := p.SetPolicyInfo(
        policyprovider.IntegrationInfo{Name: "azure", Key: key},
        policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: appId},
        []hexapolicy.PolicyInfo{{
            Meta:    hexapolicy.MetaInfo{Version: "0"},
            Actions: []hexapolicy.ActionInfo{{"azure:GET/not_defined"}},
            Subjects: []string{
                "user:" + policytestsupport.UserEmailGetHrUs,
                "user:" + policytestsupport.UserEmailGetProfile},
            Object: hexapolicy.ObjectInfo{
                ResourceID: policytestsupport.PolicyObjectResourceId,
            },
        }})

    assert.NoError(t, err)
    assert.Equal(t, http.StatusCreated, status)
    mockAzClient.AssertExpectations(t)
}

func TestSetPolicy(t *testing.T) {
    appId := azuretestsupport.AzureAppId
    key := azuretestsupport.AzureKeyBytes()

    mockAzClient := azuretestsupport.NewMockAzureClient()
    mockAzClient.ExpectGetServicePrincipals()
    mockAzClient.ExpectGetPrincipalIdFromEmail(policytestsupport.UserEmailGetHrUs, policytestsupport.UserIdGetHrUs)
    mockAzClient.ExpectSetAppRoleAssignedTo(azuretestsupport.AppRoleAssignmentGetHrUs)

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))
    status, err := p.SetPolicyInfo(
        policyprovider.IntegrationInfo{Name: "azure", Key: key},
        policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: appId},
        []hexapolicy.PolicyInfo{{
            Meta:     hexapolicy.MetaInfo{Version: "0"},
            Actions:  []hexapolicy.ActionInfo{{"azure:" + policytestsupport.ActionGetHrUs}},
            Subjects: []string{"user:" + policytestsupport.UserEmailGetHrUs},
            Object: hexapolicy.ObjectInfo{
                ResourceID: policytestsupport.PolicyObjectResourceId,
            },
        }})

    assert.NoError(t, err)
    assert.Equal(t, http.StatusCreated, status)
    mockAzClient.AssertExpectations(t)
}

func TestSetPolicy_RemovedAllMembers_FromOnePolicy(t *testing.T) {
    appId := azuretestsupport.AzureAppId
    key := azuretestsupport.AzureKeyBytes()

    mockAzClient := azuretestsupport.NewMockAzureClient()
    mockAzClient.ExpectGetServicePrincipals()
    mockAzClient.ExpectSetAppRoleAssignedTo(
        azuretestsupport.AssignmentsForDelete(azuretestsupport.AppRoleAssignmentGetHrUs))

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))
    status, err := p.SetPolicyInfo(
        policyprovider.IntegrationInfo{Name: "azure", Key: key},
        policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: appId},
        []hexapolicy.PolicyInfo{{
            Meta:     hexapolicy.MetaInfo{Version: "0"},
            Actions:  []hexapolicy.ActionInfo{{"azure:" + policytestsupport.ActionGetHrUs}},
            Subjects: []string{},
            Object: hexapolicy.ObjectInfo{
                ResourceID: policytestsupport.PolicyObjectResourceId,
            },
        }})

    assert.NoError(t, err)
    assert.Equal(t, http.StatusCreated, status)
    mockAzClient.AssertExpectations(t)
}

func TestSetPolicy_RemovedAllMembers_FromAllPolicies(t *testing.T) {
    appId := azuretestsupport.AzureAppId
    key := azuretestsupport.AzureKeyBytes()

    mockAzClient := azuretestsupport.NewMockAzureClient()
    mockAzClient.ExpectGetServicePrincipals()
    mockAzClient.ExpectSetAppRoleAssignedTo(
        azuretestsupport.AssignmentsForDelete(azuretestsupport.AppRoleAssignmentGetHrUs))
    mockAzClient.ExpectSetAppRoleAssignedTo(
        azuretestsupport.AssignmentsForDelete(azuretestsupport.AppRoleAssignmentGetProfile))

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))
    status, err := p.SetPolicyInfo(
        policyprovider.IntegrationInfo{Name: "azure", Key: key},
        policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: appId},
        []hexapolicy.PolicyInfo{
            {
                Meta:     hexapolicy.MetaInfo{Version: "0"},
                Actions:  []hexapolicy.ActionInfo{{"azure:" + policytestsupport.ActionGetHrUs}},
                Subjects: []string{},
                Object: hexapolicy.ObjectInfo{
                    ResourceID: policytestsupport.PolicyObjectResourceId,
                },
            },
            {
                Meta:     hexapolicy.MetaInfo{Version: "0"},
                Actions:  []hexapolicy.ActionInfo{{"azure:" + policytestsupport.ActionGetProfile}},
                Subjects: []string{},
                Object: hexapolicy.ObjectInfo{
                    ResourceID: policytestsupport.PolicyObjectResourceId,
                },
            },
        })

    assert.NoError(t, err)
    assert.Equal(t, http.StatusCreated, status)
    mockAzClient.AssertExpectations(t)
}

func TestSetPolicy_MultipleAppRolePolicies(t *testing.T) {
    appId := azuretestsupport.AzureAppId
    key := azuretestsupport.AzureKeyBytes()

    mockAzClient := azuretestsupport.NewMockAzureClient()
    mockAzClient.ExpectGetServicePrincipals()
    mockAzClient.ExpectGetPrincipalIdFromEmail(policytestsupport.UserEmailGetHrUs, policytestsupport.UserIdGetHrUs)
    mockAzClient.ExpectGetPrincipalIdFromEmail(policytestsupport.UserEmailGetProfile, policytestsupport.UserIdGetProfile)

    mockAzClient.ExpectSetAppRoleAssignedTo(azuretestsupport.AppRoleAssignmentGetHrUs)
    mockAzClient.ExpectSetAppRoleAssignedTo(azuretestsupport.AppRoleAssignmentGetProfile)

    p := azureProvider.NewAzureProvider(azureProvider.WithAzureClient(mockAzClient))
    status, err := p.SetPolicyInfo(
        policyprovider.IntegrationInfo{Name: "azure", Key: key},
        policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: appId},
        []hexapolicy.PolicyInfo{
            {
                Meta:     hexapolicy.MetaInfo{Version: "0"},
                Actions:  []hexapolicy.ActionInfo{{"azure:" + policytestsupport.ActionGetHrUs}},
                Subjects: []string{"user:" + policytestsupport.UserEmailGetHrUs},
                Object: hexapolicy.ObjectInfo{
                    ResourceID: policytestsupport.PolicyObjectResourceId,
                },
            },
            {
                Meta:     hexapolicy.MetaInfo{Version: "0"},
                Actions:  []hexapolicy.ActionInfo{{"azure:" + policytestsupport.ActionGetProfile}},
                Subjects: []string{"user:" + policytestsupport.UserEmailGetProfile},
                Object: hexapolicy.ObjectInfo{
                    ResourceID: policytestsupport.PolicyObjectResourceId,
                },
            },
        })

    assert.NoError(t, err)
    assert.Equal(t, http.StatusCreated, status)
    mockAzClient.AssertExpectations(t)
}
