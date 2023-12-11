package avp_test

import (
	"net/http"
	"testing"

	"github.com/hexa-org/policy-mapper/api/PolicyProvider"
	"github.com/hexa-org/policy-mapper/providers/aws/avp"
	"github.com/hexa-org/policy-mapper/providers/aws/avp/avpClient/avpTestSupport"

	"github.com/hexa-org/policy-mapper/providers/aws/awscommon"
	"github.com/stretchr/testify/assert"
)

type TestInfo struct {
	Apps     []PolicyProvider.ApplicationInfo
	Provider avp.AmazonAvpProvider
	Info     PolicyProvider.IntegrationInfo
}

func TestAvp_1_ListStores(t *testing.T) {
	mockClient := avpTestSupport.NewMockVerifiedPermissionsHTTPClient()
	mockClient.MockListStores()

	p := avp.AmazonAvpProvider{AwsClientOpts: awscommon.AWSClientOptions{
		HTTPClient:   mockClient,
		DisableRetry: true,
	}}

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

	p := avp.AmazonAvpProvider{AwsClientOpts: awscommon.AWSClientOptions{
		HTTPClient:   mockClient,
		DisableRetry: true,
	}}

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
