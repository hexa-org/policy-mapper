package avpClient

import (
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"
	"github.com/hexa-org/policy-mapper/api/PolicyProvider"
	"github.com/hexa-org/policy-mapper/providers/aws/avp/avpClient/avpTestSupport"
	"github.com/hexa-org/policy-mapper/providers/aws/awscommon"
	"github.com/stretchr/testify/assert"
)

type TestInfo struct {
	App           PolicyProvider.ApplicationInfo
	hexaAvpClient AvpClient
	vpClient      *verifiedpermissions.Client
	mockClient    *avpTestSupport.MockVerifiedPermissionsHTTPClient
}

var testInfo TestInfo

func TestAvpClient_1_ListStores(t *testing.T) {
	mockClient := avpTestSupport.NewMockVerifiedPermissionsHTTPClient()
	key := avpTestSupport.AwsCredentialsForTest()
	hexaClient, err := NewAvpClient(key, awscommon.AWSClientOptions{
		HTTPClient:   mockClient,
		DisableRetry: true,
	})
	assert.NoError(t, err, "Should be no error on NewAvpClient")
	testInfo = TestInfo{
		hexaAvpClient: hexaClient,
		mockClient:    mockClient,
	}

	testInfo.mockClient.MockListStores()
	apps, err := testInfo.hexaAvpClient.ListStores()
	assert.NoError(t, err, "Should be no error on ListStores")
	assert.Len(t, apps, 1, "Should be 1 store defined")
	assert.Equal(t, avpTestSupport.TestPolicyStoreDescription, apps[0].Description)
	assert.True(t, mockClient.VerifyCalled())

	// Save for future use
	testInfo.App = apps[0]

	testInfo.mockClient.MockListStoresWithHttpStatus(http.StatusUnauthorized)
	apps2, err := testInfo.hexaAvpClient.ListStores()
	assert.Error(t, err)
	assert.Nil(t, apps2)
	// assert.Equal(t, avpTestSupport.TestPolicyStoreDescription, apps[0].Description)
	assert.True(t, mockClient.VerifyCalled())
}

func TestAvpClient_2_ListPolicies(t *testing.T) {
	// error test
	testInfo.mockClient.MockListPoliciesWithHttpStatus(http.StatusBadRequest, 1, 1, nil)
	noItems, err := testInfo.hexaAvpClient.ListPolicies(testInfo.App)
	assert.Error(t, err, "Should be a bad request error")
	assert.Nil(t, noItems, "Should be no items")
	assert.True(t, testInfo.mockClient.VerifyCalled())

	// Test when no paging needed
	testInfo.mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 1, 1, nil)

	policyItems, err := testInfo.hexaAvpClient.ListPolicies(testInfo.App)
	assert.NoError(t, err, "List policy should have no error")
	assert.Len(t, policyItems, 2, "Should be 2 policies")
	pid := *policyItems[0].PolicyId
	assert.Equal(t, avpTestSupport.TestCedarStaticPolicyId+"0", pid)
	pid = *policyItems[1].PolicyId
	assert.Equal(t, avpTestSupport.TestCedarTemplatePolicyId+"0", pid)
	assert.True(t, testInfo.mockClient.VerifyCalled())

	// Testing paging
	testInfo.mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 30, 30, nil)
	nextToken := "50"
	testInfo.mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 5, 5, &nextToken)

	policyItems2, err := testInfo.hexaAvpClient.ListPolicies(testInfo.App)
	assert.NoError(t, err, "List policy should have no error")
	assert.Len(t, policyItems2, 60, "Should be 60 policies")
	assert.True(t, testInfo.mockClient.VerifyCalled())
}

func TestAvpClient_3_GetPolicy(t *testing.T) {
	testInfo.mockClient.MockGetPolicyWithHttpStatus(http.StatusBadRequest, "123")
	noPolicy, err := testInfo.hexaAvpClient.GetPolicy("123", testInfo.App)
	assert.Error(t, err, "Should be a bad request error")
	assert.Nil(t, noPolicy, "Should be null policy")
	assert.True(t, testInfo.mockClient.VerifyCalled())

	testInfo.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, "123")
	policyItem, err := testInfo.hexaAvpClient.GetPolicy("123", testInfo.App)
	assert.NoError(t, err, "Should be no error on GetPolicy")
	var expected *verifiedpermissions.GetPolicyOutput
	assert.IsType(t, expected, policyItem, "Should be GetPolicyOutput")

	defDetail := policyItem.Definition
	staticDef := defDetail.(*types.PolicyDefinitionDetailMemberStatic).Value
	assert.NotNil(t, staticDef.Statement)
	assert.True(t, testInfo.mockClient.VerifyCalled())
}

func TestAvpClient_4_GetTemplatePolicy(t *testing.T) {
	testInfo.mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusBadRequest, "123")
	noPolicy, err := testInfo.hexaAvpClient.GetTemplatePolicy("123", testInfo.App)
	assert.Error(t, err, "Should be a bad request error")
	assert.Nil(t, noPolicy, "Should be null policy")
	assert.True(t, testInfo.mockClient.VerifyCalled())

	testInfo.mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, "123")
	policyItem, err := testInfo.hexaAvpClient.GetTemplatePolicy("123", testInfo.App)
	assert.NoError(t, err, "Should be no error on GetPolicy")
	var expected *verifiedpermissions.GetPolicyTemplateOutput
	assert.IsType(t, expected, policyItem, "Should be GetPolicyOutput")
	expected = policyItem
	assert.NotNil(t, expected.Statement)
	assert.True(t, testInfo.mockClient.VerifyCalled())
}

func TestAvpClient_5_CreatePolicy(t *testing.T) {
	testInfo.mockClient.MockCreatePolicyWithHttpStatus(http.StatusBadRequest, "123")

	createPolicyDefinition := types.StaticPolicyDefinition{
		Statement:   &avpTestSupport.TestCedarStaticPolicy,
		Description: &avpTestSupport.TestCedarStaticPolicyDescription,
	}
	createStatic := types.PolicyDefinitionMemberStatic{
		Value: createPolicyDefinition,
	}
	createPolicyInput := verifiedpermissions.CreatePolicyInput{
		Definition:    &createStatic,
		PolicyStoreId: &avpTestSupport.TestPolicyStoreId,
	}

	noOutput, err := testInfo.hexaAvpClient.CreatePolicy(&createPolicyInput)
	assert.Error(t, err, "Should be a bad request error")
	assert.Nil(t, noOutput, "Should be null output")
	assert.True(t, testInfo.mockClient.VerifyCalled())

	testInfo.mockClient.MockCreatePolicyWithHttpStatus(http.StatusOK, "123")
	output, err := testInfo.hexaAvpClient.CreatePolicy(&createPolicyInput)
	assert.NoError(t, err)
	assert.NotNil(t, output)
	id := *output.PolicyId
	assert.Equal(t, "123", id)
	assert.True(t, testInfo.mockClient.VerifyCalled())
}

func TestAvpClient_6_UpdatePolicy(t *testing.T) {
	testInfo.mockClient.MockUpdatePolicyWithHttpStatus(http.StatusBadRequest, "123")

	updatePolicyDefinition := types.UpdateStaticPolicyDefinition{
		Statement:   &avpTestSupport.TestCedarStaticPolicy,
		Description: &avpTestSupport.TestCedarStaticPolicyDescription,
	}

	updateMemberStatic := types.UpdatePolicyDefinitionMemberStatic{Value: updatePolicyDefinition}
	update := verifiedpermissions.UpdatePolicyInput{
		Definition:    &updateMemberStatic,
		PolicyId:      &avpTestSupport.TestCedarStaticPolicyId,
		PolicyStoreId: &avpTestSupport.TestPolicyStoreId,
	}

	noOutput, err := testInfo.hexaAvpClient.UpdatePolicy(&update)
	assert.Error(t, err, "Should be a bad request error")
	assert.Nil(t, noOutput, "Should be null output")
	assert.True(t, testInfo.mockClient.VerifyCalled())

	testInfo.mockClient.MockUpdatePolicyWithHttpStatus(http.StatusOK, "123")
	output, err := testInfo.hexaAvpClient.UpdatePolicy(&update)
	assert.NoError(t, err)
	assert.NotNil(t, output)
	id := *output.PolicyId
	assert.Equal(t, "123", id)
	assert.True(t, testInfo.mockClient.VerifyCalled())
}

func TestAvpClient_7_DeletePolicy(t *testing.T) {
	testInfo.mockClient.MockDeletePolicyWithHttpStatus(http.StatusBadRequest)

	pId := "123"
	deletePolicyInput := verifiedpermissions.DeletePolicyInput{
		PolicyId:      &pId,
		PolicyStoreId: &avpTestSupport.TestPolicyStoreId,
	}

	noOutput, err := testInfo.hexaAvpClient.DeletePolicy(&deletePolicyInput)
	assert.Error(t, err, "Should be a bad request error")
	assert.Nil(t, noOutput, "Should be null output")
	assert.True(t, testInfo.mockClient.VerifyCalled())

	testInfo.mockClient.MockDeletePolicyWithHttpStatus(http.StatusOK)
	output, err := testInfo.hexaAvpClient.DeletePolicy(&deletePolicyInput)
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.True(t, testInfo.mockClient.VerifyCalled())
}
