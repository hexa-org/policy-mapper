package cognitoProvider_test

import (
    "net/http"
    "testing"

    "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
    "github.com/hexa-org/policy-mapper/api/policyprovider"
    "github.com/hexa-org/policy-mapper/models/rar/testsupport/awstestsupport"
    "github.com/hexa-org/policy-mapper/models/rar/testsupport/cognitotestsupport"
    "github.com/hexa-org/policy-mapper/models/rar/testsupport/policytestsupport"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
    "github.com/hexa-org/policy-mapper/providers/aws/awscommon"
    "github.com/hexa-org/policy-mapper/providers/aws/cognitoProvider"

    "github.com/stretchr/testify/assert"
)

func TestAmazonProvider_DiscoverApplications(t *testing.T) {
    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    p := cognitoProvider.CognitoProvider{AwsClientOpts: awscommon.AWSClientOptions{DisableRetry: true}}
    _, err := p.DiscoverApplications(info)
    assert.Error(t, err, "operation error Cognito Identity Provider: ListUserPools, expected endpoint resolver to not be nil")
}

func TestAmazonProvider_DiscoverApplications_withOtherProvider(t *testing.T) {
    p := &cognitoProvider.CognitoProvider{}
    info := policyprovider.IntegrationInfo{Name: "not_amazon", Key: []byte("aKey")}
    apps, err := p.DiscoverApplications(info)
    assert.NoError(t, err)
    assert.Empty(t, apps)
}

func TestAmazonProvider_ListUserPools_ErrorCallingListUserPoolsApi(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    mockClient.MockListUserPoolsWithHttpStatus(http.StatusBadRequest)

    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    apps, err := p.DiscoverApplications(info)
    assert.Error(t, err)
    assert.ErrorContains(t, err, "error StatusCode: 400")
    assert.ErrorContains(t, err, "ListUserPools")
    assert.Empty(t, apps)
    assert.True(t, mockClient.VerifyCalled())
}

func TestAmazonProvider_ListUserPools_ErrorCallingListResourceServicesApi(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    mockClient.MockListUserPools()
    mockClient.MockListResourceServersWithHttpStatus(http.StatusBadRequest, cognitoidentityprovider.ListResourceServersOutput{})

    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    apps, err := p.DiscoverApplications(info)
    assert.Error(t, err)
    assert.ErrorContains(t, err, "error StatusCode: 400")
    assert.ErrorContains(t, err, "ListResourceServers")
    assert.Empty(t, apps)
    assert.True(t, mockClient.VerifyCalled())
}

func TestAmazonProvider_ListUserPools_Success(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    mockClient.MockListUserPools()
    mockClient.MockListResourceServers(cognitotestsupport.WithResourceServer())
    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    apps, err := p.DiscoverApplications(info)
    assert.NoError(t, err)
    assert.Len(t, apps, 1)
    assert.Equal(t, awstestsupport.TestUserPoolId, apps[0].ObjectID)
    assert.Equal(t, awstestsupport.TestResourceServerName, apps[0].Name)
    assert.Equal(t, awstestsupport.TestResourceServerIdentifier, apps[0].Service)
    assert.Equal(t, "Resource: some-resource-server-name, UserPool: some-user-pool-name", apps[0].Description)
    assert.True(t, mockClient.VerifyCalled())
}

func TestAmazonProvider_GetPolicyInfo_CognitoClientError(t *testing.T) {
    p := cognitoProvider.CognitoProvider{}
    info := policyprovider.IntegrationInfo{Name: cognitoProvider.ProviderTypeAwsCognito, Key: []byte("!!!")}
    appInfo := awstestsupport.AppInfo()
    policyInfo, err := p.GetPolicyInfo(info, appInfo)
    assert.Error(t, err)
    assert.ErrorContains(t, err, "invalid character")
    assert.Nil(t, policyInfo)
}

func TestAmazonProvider_GetPolicyInfo(t *testing.T) {
    // TODO - investigate why this test is flaky. Something to do with the ProcessAsync call
    t.Skip("Skip flaky test TestAmazonProvider_GetPolicyInfo")
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    mockClient.MockListGroups(policytestsupport.ActionGetProfile, policytestsupport.ActionGetHrUs)
    mockClient.MockListUsersInGroup(policytestsupport.UserIdGetProfile)
    mockClient.MockAdminGetUser(policytestsupport.UserIdGetProfile, policytestsupport.UserEmailGetProfile)
    mockClient.MockListUsersInGroup(policytestsupport.UserIdGetHrUs)
    mockClient.MockAdminGetUser(policytestsupport.UserIdGetHrUs, policytestsupport.UserEmailGetHrUs)

    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    appInfo := awstestsupport.AppInfo()
    actualPolicies, err := p.GetPolicyInfo(info, appInfo)
    assert.NoError(t, err)
    assert.NotEmpty(t, actualPolicies)
    expActionMembers := map[string][]string{
        policytestsupport.ActionGetProfile: {policytestsupport.UserEmailGetProfile},
        policytestsupport.ActionGetHrUs:    {policytestsupport.UserEmailGetHrUs},
    }

    expPolicies := policytestsupport.MakePolicies(expActionMembers, awstestsupport.TestResourceServerName)
    assert.Equal(t, len(expPolicies), len(actualPolicies))
    assert.True(t, policytestsupport.ContainsPolicies(t, expPolicies, actualPolicies))
    assert.True(t, mockClient.VerifyCalled())
}

func TestAmazonProvider_GetPolicyInfo_withListGroupsError(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()

    mockClient.MockListGroupsWithHttpStatus(http.StatusBadRequest, policytestsupport.ActionGetProfile, policytestsupport.ActionGetHrUs)
    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    appInfo := awstestsupport.AppInfo()
    _, err := p.GetPolicyInfo(info, appInfo)
    assert.Error(t, err)
    assert.ErrorContains(t, err, "error StatusCode: 400")
}

func TestSetPolicy_withInvalidArguments(t *testing.T) {
    key := []byte("key")
    p := cognitoProvider.CognitoProvider{}

    status, err := p.SetPolicyInfo(
        policyprovider.IntegrationInfo{Name: "azure", Key: key},
        policyprovider.ApplicationInfo{Name: "anAppName", Description: "anAppId"},
        []hexapolicy.PolicyInfo{{
            Meta:     hexapolicy.MetaInfo{Version: "0"},
            Actions:  []hexapolicy.ActionInfo{"azure:anAppRoleId"},
            Subjects: []string{"aPrincipalId:aPrincipalDisplayName", "yetAnotherPrincipalId:yetAnotherPrincipalDisplayName", "andAnotherPrincipalId:andAnotherPrincipalDisplayName"},
            Object:   "anObjectId",
        }})

    assert.Equal(t, http.StatusInternalServerError, status)
    assert.EqualError(t, err, "Key: 'ApplicationInfo.ObjectID' Error:Field validation for 'ObjectID' failed on the 'required' tag")

    /* test not valid after restructure
       status, err = p.SetPolicyInfo(
           policyprovider.IntegrationInfo{Name: "azure", Key: key},
           policyprovider.ApplicationInfo{ObjectID: "anObjectId", Name: "anAppName", Description: "aDescription"},
           []hexapolicy.PolicyInfo{{
               Meta:     hexapolicy.MetaInfo{Version: "0"},
               Actions:  []hexapolicy.ActionInfo{"azure:anAppRoleId"},
               Subjects: []string{"aPrincipalId:aPrincipalDisplayName", "yetAnotherPrincipalId:yetAnotherPrincipalDisplayName", "andAnotherPrincipalId:andAnotherPrincipalDisplayName"},
               Object:   nil,
           }})

       assert.Equal(t, http.StatusInternalServerError, status)
       assert.EqualError(t, err, "Key: '[0].Object' Error:Field validation for 'ResourceID' failed on the 'required' tag")
    */
}

func TestSetPolicyInfo_CognitoClientError(t *testing.T) {
    p := cognitoProvider.CognitoProvider{}
    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    info.Key = []byte("!!!!")
    appInfo := awstestsupport.AppInfo()
    _, err := p.SetPolicyInfo(info, appInfo, []hexapolicy.PolicyInfo{})
    assert.Error(t, err)
    assert.ErrorContains(t, err, "invalid character '!'")
}

func TestSetPolicyInfo_ListGroupsError(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    mockClient.MockListGroupsWithHttpStatus(http.StatusBadRequest)
    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    appInfo := awstestsupport.AppInfo()
    _, err := p.SetPolicyInfo(info, appInfo, []hexapolicy.PolicyInfo{})
    assert.Error(t, err)
    assert.ErrorContains(t, err, "ListGroups")
    assert.ErrorContains(t, err, "error StatusCode: 400")
}

func TestSetPolicyInfo_NoPoliciesInput(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    expGroups := []string{policytestsupport.ActionGetProfile, policytestsupport.ActionGetHrUs}
    mockClient.MockListGroups(expGroups...)

    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    appInfo := awstestsupport.AppInfo()
    status, err := p.SetPolicyInfo(info, appInfo, []hexapolicy.PolicyInfo{})
    assert.NoError(t, err)
    assert.Equal(t, http.StatusCreated, status)
}

func TestSetPolicyInfo_ListUsersInGroupError(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    expGroups := []string{policytestsupport.ActionGetProfile, policytestsupport.ActionGetHrUs}
    mockClient.MockListGroups(expGroups...)
    mockClient.MockListUsersInGroupWithHttpStatus(http.StatusBadRequest)

    actionMemberMap := policytestsupport.MakeActionMembers()

    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    appInfo := awstestsupport.AppInfo()

    expPolicies := policytestsupport.MakeTestPolicies(actionMemberMap)
    _, err := p.SetPolicyInfo(info, appInfo, expPolicies)
    assert.Error(t, err)
    assert.ErrorContains(t, err, "ListUsersInGroup")
    assert.ErrorContains(t, err, "error StatusCode: 400")
}

func TestSetPolicyInfo_IgnoresNotFoundPrincipal(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    expGroups := []string{policytestsupport.ActionGetHrUs}
    mockClient.MockListGroups(expGroups...)

    actionMemberMap := map[string]policytestsupport.ActionMembers{
        policytestsupport.ActionGetHrUs: {
            MemberIds: []string{policytestsupport.UserIdGetHrUs, ""},
            Emails:    []string{policytestsupport.UserEmailGetHrUs, policytestsupport.UserEmailGetHrUsAndProfile},
        },
    }
    for range actionMemberMap {
        mockClient.MockListUsersInGroup()
    }

    for _, actionMem := range actionMemberMap {
        for _, principalId := range actionMem.MemberIds {
            mockClient.MockListUsers(principalId)
            if principalId != "" {
                mockClient.MockAdminAddUserToGroup()
            }
        }
    }

    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    appInfo := awstestsupport.AppInfo()
    expPolicies := policytestsupport.MakeTestPolicies(actionMemberMap)
    _, err := p.SetPolicyInfo(info, appInfo, expPolicies)
    assert.NoError(t, err)
    assert.True(t, mockClient.VerifyCalled())
}

func TestSetPolicyInfo_AddUserToGroupError(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    expGroups := []string{policytestsupport.ActionGetProfile, policytestsupport.ActionGetHrUs}
    mockClient.MockListGroups(expGroups...)

    actionMemberMap := policytestsupport.MakeActionMembers()
    mockClient.MockListUsersInGroup()
    for _, principalId := range actionMemberMap[expGroups[0]].MemberIds {
        mockClient.MockListUsers(principalId)
    }

    mockClient.MockAdminAddUserToGroupWithHttpStatus(http.StatusBadRequest)

    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    appInfo := awstestsupport.AppInfo()
    expPolicies := policytestsupport.MakeTestPolicies(actionMemberMap)
    stat, err := p.SetPolicyInfo(info, appInfo, expPolicies)
    assert.Equal(t, http.StatusInternalServerError, stat)
    assert.Error(t, err)
    assert.ErrorContains(t, err, "AdminAddUserToGroup")
    assert.ErrorContains(t, err, "error StatusCode: 400")
    assert.True(t, mockClient.VerifyCalled())
}

func TestSetPolicyInfo_RemoveUserFromGroupError(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    expGroups := []string{policytestsupport.ActionGetProfile, policytestsupport.ActionGetHrUs}
    mockClient.MockListGroups(expGroups...)

    actionMemberMap := map[string]policytestsupport.ActionMembers{
        policytestsupport.ActionGetProfile: {
            MemberIds: []string{policytestsupport.UserIdGetProfile, policytestsupport.UserIdGetHrUsAndProfile},
        },
        policytestsupport.ActionGetHrUs: {
            MemberIds: []string{policytestsupport.UserIdGetHrUs, policytestsupport.UserIdGetHrUsAndProfile},
        },
    }

    mockClient.MockListUsersInGroup(actionMemberMap[expGroups[0]].MemberIds...)
    for _, principalId := range actionMemberMap[expGroups[0]].MemberIds {
        mockClient.MockAdminGetUser(principalId, "random@email.io")
    }

    mockClient.MockAdminRemoveUserFromGroupWithHttpStatus(http.StatusBadRequest)

    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    appInfo := awstestsupport.AppInfo()
    expPolicies := policytestsupport.MakeTestPolicies(actionMemberMap)
    stat, err := p.SetPolicyInfo(info, appInfo, expPolicies)
    assert.Equal(t, http.StatusInternalServerError, stat)
    assert.Error(t, err)
    assert.ErrorContains(t, err, "AdminRemoveUserFromGroup")
    assert.ErrorContains(t, err, "error StatusCode: 400")
    assert.True(t, mockClient.VerifyCalled())
}

func TestSetPolicyInfo_RemoveAllExistingAssignments(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    expGroups := []string{policytestsupport.ActionGetProfile, policytestsupport.ActionGetHrUs}
    mockClient.MockListGroups(expGroups...)

    actionMemberMap := map[string]policytestsupport.ActionMembers{
        policytestsupport.ActionGetProfile: {
            MemberIds: []string{policytestsupport.UserIdGetProfile, policytestsupport.UserIdGetHrUsAndProfile},
        },
        policytestsupport.ActionGetHrUs: {
            MemberIds: []string{policytestsupport.UserIdGetHrUs, policytestsupport.UserIdGetHrUsAndProfile},
        },
    }

    for _, actionMem := range actionMemberMap {
        mockClient.MockListUsersInGroup(actionMem.MemberIds...)
        for _, principalId := range actionMem.MemberIds {
            mockClient.MockAdminGetUser(principalId, "random@email.io")
            mockClient.MockAdminRemoveUserFromGroup()
        }
    }

    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    appInfo := awstestsupport.AppInfo()
    expPolicies := policytestsupport.MakeTestPolicies(actionMemberMap)
    _, err := p.SetPolicyInfo(info, appInfo, expPolicies)
    assert.NoError(t, err)
    assert.True(t, mockClient.VerifyCalled())
}

func TestSetPolicyInfo_NoExistingAssignments_AddAll(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    expGroups := []string{policytestsupport.ActionGetProfile, policytestsupport.ActionGetHrUs}
    mockClient.MockListGroups(expGroups...)

    actionMemberMap := policytestsupport.MakeActionMembers()
    for range actionMemberMap {
        mockClient.MockListUsersInGroup()
    }

    for _, actionMem := range actionMemberMap {
        for _, principalId := range actionMem.MemberIds {
            mockClient.MockListUsers(principalId)
            mockClient.MockAdminAddUserToGroup()
        }
    }

    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    appInfo := awstestsupport.AppInfo()
    expPolicies := policytestsupport.MakeTestPolicies(actionMemberMap)
    _, err := p.SetPolicyInfo(info, appInfo, expPolicies)
    assert.NoError(t, err)
    assert.True(t, mockClient.VerifyCalled())
}

func TestSetPolicyInfo_NoneAddedOrRemoved(t *testing.T) {
    mockClient := cognitotestsupport.NewMockCognitoHTTPClient()
    expGroups := []string{policytestsupport.ActionGetProfile, policytestsupport.ActionGetHrUs}
    mockClient.MockListGroups(expGroups...)

    actionMemberMap := policytestsupport.MakeActionMembers()
    for _, actionMem := range actionMemberMap {
        mockClient.MockListUsersInGroup(actionMem.MemberIds...)
        for p, principalId := range actionMem.MemberIds {
            mockClient.MockAdminGetUser(principalId, actionMem.Emails[p])
            mockClient.MockListUsers(principalId)
        }
    }

    p := cognitoProvider.CognitoProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true}}

    info := awstestsupport.IntegrationInfo(cognitoProvider.ProviderTypeAwsCognito)
    appInfo := awstestsupport.AppInfo()
    expPolicies := policytestsupport.MakeTestPolicies(actionMemberMap)
    _, err := p.SetPolicyInfo(info, appInfo, expPolicies)
    assert.NoError(t, err)
    assert.True(t, mockClient.VerifyCalled())
}
