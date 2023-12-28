package sdk

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/hexa-org/policy-mapper/api/PolicyProvider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/providers/aws/avp"
	"github.com/hexa-org/policy-mapper/providers/aws/avp/avpClient/avpTestSupport"
	"github.com/hexa-org/policy-mapper/providers/aws/awscommon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var testLog = log.New(os.Stdout, "SDK-TEST: ", log.Ldate|log.Ltime)

type testSuite struct {
	suite.Suite
	Integration *Integration
	Info        PolicyProvider.IntegrationInfo
	papId       string
	mockClient  *avpTestSupport.MockVerifiedPermissionsHTTPClient
}

func TestSdk(t *testing.T) {

	mockClient := avpTestSupport.NewMockVerifiedPermissionsHTTPClient()

	options := awscommon.AWSClientOptions{
		HTTPClient:   mockClient,
		DisableRetry: true,
	}
	info := avpTestSupport.IntegrationInfo()
	integration, err := OpenIntegration(&info, WithProviderOptions(options))
	assert.NoError(t, err, "Check no error opening mock provider")
	s := testSuite{
		Info:        info,
		Integration: integration,
		mockClient:  mockClient,
	}

	suite.Run(t, &s)

	testLog.Println("** SDK Tests Complete **")

}

func (s *testSuite) Test1_GetPaps() {
	s.mockClient.MockListStores()

	apps, err := s.Integration.GetPolicyApplicationPoints(nil)
	assert.NoError(s.T(), err, "Check no error for get PAPs")
	assert.Len(s.T(), apps, 1, "Should be 1 app")
	assert.Len(s.T(), s.Integration.Apps, len(apps))
	s.papId = apps[0].ObjectID // save for the next test
	s.mockClient.VerifyCalled()
}

func (s *testSuite) Test2_GetPolicies() {
	s.mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 1, 1, nil)
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
	s.mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")

	policies, err := s.Integration.GetPolicies(s.papId)

	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), policies)
	assert.Len(s.T(), policies, 2, "Should be 2 policies")
	assert.True(s.T(), s.mockClient.VerifyCalled())
}

func (s *testSuite) Test3_Reconcile() {
	s.mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 5, 1, nil)
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"1")
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"2")
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"3")
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"4")
	s.mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")

	policies, err := s.Integration.GetPolicies(s.papId)

	assert.True(s.T(), s.mockClient.VerifyCalled())

	// origPolicies := policies[0:]
	// This section will cause an update since only action changed
	policy := policies[0]
	actions := policy.Actions

	actions = append(actions, hexapolicy.ActionInfo{ActionUri: "cedar:hexa_avp::Action::\"UpdateAccount\""})

	policies[0].Actions = actions

	avpMeta := policies[1].Meta
	var avpType string
	avpType, exist := avpMeta.SourceData[avp.ParamPolicyType].(string)
	assert.True(s.T(), exist, "Check policy type exists")
	assert.Equal(s.T(), "TEMPLATE_LINKED", avpType, "Second [1] policy should be template")

	// this should cause a replacement (delete and add) to occur (subject change)
	policies[2].Subject.Members = []string{"hexa_avp::User::\"gerry@strata.io\""}

	// this should cause an implied delete by removing policy 5
	policies = append(policies[0:5], policies[6:]...)

	now := time.Now()
	// now append a policy by copying and modifying the first
	newPolicy := policies[0]
	newPolicy.Meta = hexapolicy.MetaInfo{
		Version:     "0.5",
		Description: "Test New Policy",
		Created:     &now,
		Modified:    &now,
	}
	newPolicy.Subject.Members = []string{"hexa_avp::User::\"nobody@strata.io\""}

	policies = append(policies, newPolicy)

	s.mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 5, 1, nil)
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"1")
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"2")
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"3")
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"4")
	s.mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")
	difs, err := s.Integration.ReconcilePolicy(s.papId, policies, true)
	assert.NoError(s.T(), err)
	assert.True(s.T(), s.mockClient.VerifyCalled())
	assert.Len(s.T(), difs, 5)
	assert.Equal(s.T(), hexapolicy.TYPE_UPDATE, difs[0].Type)
	assert.True(s.T(), slices.Equal([]string{"ACTION"}, difs[0].DifTypes))
	assert.Equal(s.T(), hexapolicy.TYPE_IGNORED, difs[1].Type)
	assert.Equal(s.T(), hexapolicy.TYPE_UPDATE, difs[2].Type)
	assert.True(s.T(), slices.Equal([]string{"SUBJECT"}, difs[2].DifTypes))
	assert.Equal(s.T(), hexapolicy.TYPE_NEW, difs[3].Type)
	assert.Equal(s.T(), hexapolicy.TYPE_DELETE, difs[4].Type)
	for _, dif := range difs {
		fmt.Println(dif.Report())
	}
}

func (s *testSuite) Test4_SetPolicies() {
	s.mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 1, 1, nil)
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
	s.mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")
	policies, err := s.Integration.GetPolicies(s.papId)
	assert.True(s.T(), s.mockClient.VerifyCalled())

	// This section will cause an update since only action changed
	policy := policies[0]
	actions := policy.Actions
	actions = append(actions, hexapolicy.ActionInfo{ActionUri: "cedar:hexa_avp::Action::\"UpdateAccount\""})

	policies[0].Actions = actions

	s.mockClient.MockListPoliciesWithHttpStatus(http.StatusOK, 1, 1, nil)
	s.mockClient.MockGetPolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
	s.mockClient.MockGetPolicyTemplateWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarTemplatePolicyId+"0")
	s.mockClient.MockUpdatePolicyWithHttpStatus(http.StatusOK, avpTestSupport.TestCedarStaticPolicyId+"0")
	status, err := s.Integration.SetPolicyInfo(s.papId, policies)
	assert.NoError(s.T(), err)
	assert.True(s.T(), s.mockClient.VerifyCalled())
	assert.Equal(s.T(), 200, status, "Should be status 200")

}
