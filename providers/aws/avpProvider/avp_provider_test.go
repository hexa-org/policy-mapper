package avpProvider_test

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "slices"
    "testing"
    "time"

    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
    "github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"
    "github.com/hexa-org/policy-mapper/api/policyprovider"
    "github.com/hexa-org/policy-mapper/models/formats/cedar"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
    "github.com/hexa-org/policy-mapper/providers/aws/avpProvider"
    "github.com/hexa-org/policy-mapper/providers/aws/avpProvider/avpClient"
    "github.com/hexa-org/policy-mapper/providers/aws/avpProvider/avpClient/avpTestSupport"

    "github.com/hexa-org/policy-mapper/providers/aws/awscommon"
    "github.com/stretchr/testify/assert"
)

type TestInfo struct {
    Apps     []policyprovider.ApplicationInfo
    Provider avpProvider.AmazonAvpProvider
    Info     policyprovider.IntegrationInfo
}

var initialized = false
var testData TestInfo

func isLiveTest() bool {
    _, ok := os.LookupEnv("AWS_LIVE")
    return ok
}

func initializeOnlineTests() error {
    if initialized {
        return nil
    }
    cfg, err := config.LoadDefaultConfig(context.TODO())
    if err != nil {
        return err
    }
    cred, err := cfg.Credentials.Retrieve(context.TODO())
    if err != nil {
        return err
    }

    str := fmt.Sprintf(`
{
  "accessKeyID": "%s",
  "secretAccessKey": "%s",
  "region": "%s"
}
`, cred.AccessKeyID, cred.SecretAccessKey, cfg.Region)

    info := policyprovider.IntegrationInfo{Name: "avp", Key: []byte(str)}
    provider := avpProvider.AmazonAvpProvider{AwsClientOpts: awscommon.AWSClientOptions{DisableRetry: true},
        CedarMapper: cedar.NewCedarMapper(map[string]string{})}

    testData = TestInfo{
        Provider: provider,
        Info:     info,
    }

    initialized = true
    return nil
}

func Test_SetPolicy_live(t *testing.T) {
    if isLiveTest() {
        var err error
        _ = initializeOnlineTests()
        apps, err := testData.Provider.DiscoverApplications(testData.Info)
        assert.NoError(t, err)

        policies, err := testData.Provider.GetPolicyInfo(testData.Info, apps[0])
        assert.NoError(t, err)
        assert.NotNil(t, policies)

        if len(policies) < 2 {
            client, err := avpClient.NewAvpClient(testData.Info.Key, testData.Provider.AwsClientOpts) // NewFromConfig(info.Key, a.AwsClientOpts)
            assert.NoError(t, err)
            // Create the template policies
            createPolicyDefinition := types.StaticPolicyDefinition{
                Statement:   &avpTestSupport.TestCedarStaticPolicy,
                Description: &avpTestSupport.TestCedarStaticPolicyDescription,
            }
            createStatic := types.PolicyDefinitionMemberStatic{
                Value: createPolicyDefinition,
            }
            createPolicyInput := verifiedpermissions.CreatePolicyInput{
                Definition:    &createStatic,
                PolicyStoreId: &apps[0].ObjectID,
            }
            _, err = client.CreatePolicy(&createPolicyInput)
            assert.NoError(t, err)
            policies, err = testData.Provider.GetPolicyInfo(testData.Info, apps[0])
            assert.NoError(t, err)
            assert.NotNil(t, policies)
        }

        // Each time this is run we add or remove the action
        policy := policies[0]
        actions := policy.Actions
        present := false
        for i, action := range actions {
            if action == "cedar:hexa_avp::Action::\"UpdateAccount\"" {
                actions = append(actions[:i], actions[i+1:]...)
                present = true
                fmt.Println("This test run will remove UpdateAccount action")
            }
        }
        if !present {
            fmt.Println("This run will add UpdateAccount action")
            actions = append(actions, "cedar:hexa_avp::Action::\"UpdateAccount\"")
        }
        policies[0].Actions = actions

        status, err := testData.Provider.SetPolicyInfo(testData.Info, apps[0], policies)
        assert.NoError(t, err)
        assert.Equal(t, 200, status, "Should be status 200")

        // this should cause a replacement (delete and add) to occur
        policies[0].Subjects = []string{"hexa_avp::User::\"gerry@strata.io\""}

        status, err = testData.Provider.SetPolicyInfo(testData.Info, apps[0], policies)
        assert.NoError(t, err)
        assert.Equal(t, 200, status, "Should be status 200")

        policies2, err := testData.Provider.GetPolicyInfo(testData.Info, apps[0])
        assert.NoError(t, err)
        assert.NotNil(t, policies2)
        assert.Len(t, policies2, 2)

        // now do the implied delete
        policies2 = policies2[1:]
        status, err = testData.Provider.SetPolicyInfo(testData.Info, apps[0], policies2)
        assert.NoError(t, err)
        assert.Equal(t, 200, status, "Should be status 200")

        policies3, err := testData.Provider.GetPolicyInfo(testData.Info, apps[0])
        assert.NoError(t, err)
        assert.NotNil(t, policies3)
        assert.Len(t, policies3, 1)

    }
}

func TestAvp_1_ListStores(t *testing.T) {
    mockClient := avpTestSupport.NewMockVerifiedPermissionsHTTPClient()
    mockClient.MockListStores()

    p := avpProvider.AmazonAvpProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true,
        },
        CedarMapper: cedar.NewCedarMapper(map[string]string{})}

    info := avpTestSupport.IntegrationInfo()
    apps, err := p.DiscoverApplications(info)
    assert.NoError(t, err)
    assert.Len(t, apps, 1)
    assert.Equal(t, avpTestSupport.TestPolicyStoreDescription, apps[0].Description)
    assert.True(t, mockClient.VerifyCalled())

    mockClient.MockListStoresWithHttpStatus(http.StatusUnauthorized)
    apps2, err := p.DiscoverApplications(info)
    assert.Error(t, err)
    assert.Nil(t, apps2)
    // assert.Equal(t, avpTestSupport.TestPolicyStoreDescription, apps[0].Description)
    assert.True(t, mockClient.VerifyCalled())
}

func TestAvp_2_GetPolicies(t *testing.T) {
    mockClient := avpTestSupport.NewMockVerifiedPermissionsHTTPClient()

    p := avpProvider.AmazonAvpProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true,
        },
        CedarMapper: cedar.NewCedarMapper(map[string]string{})}

    mockClient.MockListStores()
    info := avpTestSupport.IntegrationInfo()
    apps, err := p.DiscoverApplications(info)
    assert.NoError(t, err)
    assert.True(t, mockClient.VerifyCalled())

    mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 1, 1, nil)
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
    mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")
    policies, err := p.GetPolicyInfo(info, apps[0])
    assert.NoError(t, err)
    assert.NotNil(t, policies)
    assert.Len(t, policies, 2, "Should be 2 policies")
    assert.True(t, mockClient.VerifyCalled())
}

func TestAvp_3_Reconcile(t *testing.T) {
    mockClient := avpTestSupport.NewMockVerifiedPermissionsHTTPClient()

    p := avpProvider.AmazonAvpProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true,
        },
        CedarMapper: cedar.NewCedarMapper(map[string]string{})}

    mockClient.MockListStores()
    info := avpTestSupport.IntegrationInfo()
    apps, err := p.DiscoverApplications(info)
    assert.NoError(t, err)
    assert.True(t, mockClient.VerifyCalled())

    mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 10, 1, nil)
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"1")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"2")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"3")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"4")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"5")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"6")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"7")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"8")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"9")
    mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")
    policies, err := p.GetPolicyInfo(info, apps[0])
    assert.True(t, mockClient.VerifyCalled())

    // origPolicies := policies[0:]
    // This section will cause an update since only action changed
    policy := policies[0]
    actions := policy.Actions

    actions = append(actions, "cedar:hexa_avp::Action::\"UpdateAccount\"")

    policies[0].Actions = actions

    avpMeta := policies[1].Meta
    var avpType string
    avpType, exist := avpMeta.SourceData[avpProvider.ParamPolicyType].(string)
    assert.True(t, exist, "Check policy type exists")
    assert.Equal(t, "TEMPLATE_LINKED", avpType, "Second [1] policy should be template")

    // this should cause a replacement (delete and add) to occur (subject change)
    policies[2].Subjects = []string{"hexa_avp::User::\"gerry@strata.io\""}

    // this should cause an implied delete by removing policy 5
    policies = append(policies[0:5], policies[6:]...)

    now := time.Now()
    // now append a policy by copying and modifying the first
    newPolicy := policies[0]
    newPolicy.Meta = hexapolicy.MetaInfo{
        Version:     hexapolicy.IdqlVersion,
        Description: "Test New Policy",
        Created:     &now,
        Modified:    &now,
    }
    newPolicy.Subjects = []string{"hexa_avp::User::\"nobody@strata.io\""}

    policies = append(policies, newPolicy)

    mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 10, 1, nil)
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"1")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"2")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"3")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"4")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"5")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"6")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"7")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"8")
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"9")
    mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")
    difs, err := p.Reconcile(info, apps[0], policies, true)
    assert.NoError(t, err)
    assert.True(t, mockClient.VerifyCalled())
    assert.Len(t, difs, 5)
    assert.Equal(t, hexapolicy.ChangeTypeUpdate, difs[0].Type)
    assert.True(t, slices.Equal([]string{"ACTION"}, difs[0].DifTypes))
    assert.Equal(t, hexapolicy.ChangeTypeIgnore, difs[1].Type)
    assert.Equal(t, hexapolicy.ChangeTypeUpdate, difs[2].Type)
    assert.True(t, slices.Equal([]string{"SUBJECT"}, difs[2].DifTypes))
    assert.Equal(t, hexapolicy.ChangeTypeNew, difs[3].Type)
    assert.Equal(t, hexapolicy.ChangeTypeDelete, difs[4].Type)
    for _, dif := range difs {
        fmt.Println(dif.Report())
    }

}

func TestAvp_4_SetPolicies(t *testing.T) {
    mockClient := avpTestSupport.NewMockVerifiedPermissionsHTTPClient()

    p := avpProvider.AmazonAvpProvider{
        AwsClientOpts: awscommon.AWSClientOptions{
            HTTPClient:   mockClient,
            DisableRetry: true,
        },
        CedarMapper: cedar.NewCedarMapper(map[string]string{})}

    mockClient.MockListStores()
    info := avpTestSupport.IntegrationInfo()
    apps, err := p.DiscoverApplications(info)
    assert.NoError(t, err)
    assert.True(t, mockClient.VerifyCalled())

    mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 1, 1, nil)
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
    mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")
    policies, err := p.GetPolicyInfo(info, apps[0])
    assert.True(t, mockClient.VerifyCalled())

    // This section will cause an update since only action changed
    policy := policies[0]
    actions := policy.Actions
    present := false
    for i, action := range actions {
        if action == "cedar:hexa_avp::Action::\"UpdateAccount\"" {
            actions = append(actions[:i], actions[i+1:]...)
            present = true
            fmt.Println("This test run will remove UpdateAccount action")
        }
    }
    if !present {
        fmt.Println("This run will add UpdateAccount action")
        actions = append(actions, "cedar:hexa_avp::Action::\"UpdateAccount\"")
    }
    policies[0].Actions = actions

    mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 1, 1, nil)
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
    mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")
    mockClient.MockUpdatePolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
    status, err := p.SetPolicyInfo(info, apps[0], policies)
    assert.NoError(t, err)
    assert.True(t, mockClient.VerifyCalled())

    // this should cause a replacement (delete and add) to occur (subject change)
    policies[0].Subjects = []string{"hexa_avp::User::\"gerry@strata.io\""}

    mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 1, 1, nil)
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
    mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")
    mockClient.MockDeletePolicyWithHttpStatus(http.StatusOK)
    mockClient.MockCreatePolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
    status, err = p.SetPolicyInfo(info, apps[0], policies)
    assert.NoError(t, err)
    assert.Equal(t, 200, status, "Should be status 200")
    assert.True(t, mockClient.VerifyCalled())

    // now do the implied delete
    policies2 := policies[1:]
    mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 1, 1, nil)
    mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
    mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")
    mockClient.MockDeletePolicyWithHttpStatus(http.StatusOK)
    status, err = p.SetPolicyInfo(info, apps[0], policies2)
    assert.NoError(t, err)
    assert.Equal(t, 200, status, "Should be status 200")
    assert.True(t, mockClient.VerifyCalled())

    // now do an add policy
    mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 0, 1, nil)
    mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")
    mockClient.MockCreatePolicyWithHttpStatus(http.StatusOK, "id10")

    // Note policies has both a static and template. Initial list was mocked with only 1 template - to cause an add
    status, err = p.SetPolicyInfo(info, apps[0], policies)
    assert.NoError(t, err)
    assert.Equal(t, 200, status, "Should be status 200")
    assert.True(t, mockClient.VerifyCalled())
}

func TestAvp_5_GetSchemaLive(t *testing.T) {
    if isLiveTest() {
        var err error
        _ = initializeOnlineTests()
        apps, err := testData.Provider.DiscoverApplications(testData.Info)
        assert.NoError(t, err)

        schemaNamespaces, err := testData.Provider.GetSchema(testData.Info, apps[0])

        assert.NoError(t, err)
        assert.NotNil(t, schemaNamespaces)
        for k, schema := range *schemaNamespaces {
            assert.NotNil(t, schema.EntityTypes)
            assert.NotEmpty(t, schema.EntityTypes)
            actions := schema.Actions
            readAccountAction, ok := actions["ReadAccount"]
            ptypes := *readAccountAction.AppliesTo.PrincipalTypes

            assert.True(t, ok, "ReadAccount action not ok")
            assert.Equal(t, "User", ptypes[0])
            fmt.Println(fmt.Sprintf("Namespace: %s\n%v", k, schema))
        }

    }

}

func TestAvp_6_GetPoliciesLive(t *testing.T) {
    if isLiveTest() {

        var err error
        _ = initializeOnlineTests()
        apps, err := testData.Provider.DiscoverApplications(testData.Info)
        assert.NoError(t, err)

        policies, err := testData.Provider.GetPolicyInfo(testData.Info, apps[0])
        assert.NoError(t, err)
        assert.NotNil(t, policies)

        output, err := json.MarshalIndent(policies, "", "  ")
        assert.NoError(t, err)
        fmt.Println(string(output))
    }
}
