package sdk

import (
	"encoding/base64"
	"testing"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/providers/aws/avpProvider"
	"github.com/hexa-org/policy-mapper/providers/aws/avpProvider/avpClient/avpTestSupport"
	"github.com/hexa-org/policy-mapper/providers/aws/awscommon"
	"github.com/stretchr/testify/assert"
)

func TestWithIntegrationInfo(t *testing.T) {

	info := policyprovider.IntegrationInfo{
		Name: ProviderTypeOpa,
		Key: []byte(`
{
  "project_id": "some aws project",
  "aws": {
    "bucket_name": "opa-bundles",
    "object_name": "bundle.tar.gz",
	"key": {
      "region": "us-west-1"
    }
  }
}
`),
	}
	integration, err := OpenIntegration(WithIntegrationInfo(info))
	assert.NoError(t, err, "No error on open OPA AWS integration")
	assert.NotNil(t, integration, "Integration is defined")

	applications, err := integration.GetPolicyApplicationPoints(nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(applications))

	assert.Equal(t, "opa-bundles", applications[0].ObjectID)
	assert.Equal(t, "Open Policy Agent bundle", applications[0].Description)
	assert.Equal(t, "Hexa OPA (aws-s3)", applications[0].Service)
}

func TestWithOpaAwsIntegration(t *testing.T) {
	key := []byte(`{"region": "us-west-1"}`)
	integration, err := OpenIntegration(WithOpaAwsIntegration("opa-bundles", "bundle.tar.gz", key))
	assert.NoError(t, err, "No error on open OPA AWS integration")
	assert.NotNil(t, integration, "Integration is defined")

	applications, err := integration.GetPolicyApplicationPoints(nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(applications))

	assert.Equal(t, "opa-bundles", applications[0].ObjectID)
	assert.Equal(t, "Open Policy Agent bundle", applications[0].Description)
	assert.Equal(t, "Hexa OPA (aws-s3)", applications[0].Service)
}

func TestWithOpaGcpIntegration(t *testing.T) {
	key := []byte(`{"type": "service_account"}`)
	integration, err := OpenIntegration(
		WithOpaGcpIntegration("opa-bundles", "bundle.tar.gz", key))
	assert.NoError(t, err, "No error on open OPA GCP integration")
	assert.NotNil(t, integration, "Integration is defined")

	applications, err := integration.GetPolicyApplicationPoints(nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(applications))

	assert.Equal(t, "opa-bundles", applications[0].ObjectID)
	assert.Equal(t, "Open Policy Agent bundle", applications[0].Description)
	assert.Equal(t, "Hexa OPA (GCP_Storage)", applications[0].Service)
}

func TestWithOpaGithubIntegration(t *testing.T) {
	key := []byte(`{"accessToken": "some_github_access_token"}`)
	integration, err := OpenIntegration(
		WithOpaGithubIntegration("hexa-org", "opa-bundles", "bundle.tar.gz", key))
	assert.NoError(t, err, "No error on open OPA Github integration")
	assert.NotNil(t, integration, "Integration is defined")

	applications, err := integration.GetPolicyApplicationPoints(nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(applications))

	assert.Equal(t, "opa-bundles", applications[0].ObjectID)
	assert.Equal(t, "Open Policy Agent bundle", applications[0].Description)
	assert.Equal(t, "Hexa OPA (Github)", applications[0].Service)
}

func TestWithOpaHttpIntegration(t *testing.T) {

	integration, err := OpenIntegration(
		WithOpaHttpIntegration("aBigUrl", ""))
	assert.NoError(t, err, "No error on open OPA Http integration")
	assert.NotNil(t, integration, "Integration is defined")

	applications, err := integration.GetPolicyApplicationPoints(nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(applications))

	objectIdMatch := base64.StdEncoding.EncodeToString([]byte("aBigUrl"))
	assert.Equal(t, objectIdMatch, applications[0].ObjectID)
	assert.Equal(t, "Open Policy Agent bundle", applications[0].Description)
	assert.Equal(t, "Hexa OPA (HTTP)", applications[0].Service)
}

func TestWithAttributeMap(t *testing.T) {
	mockClient := avpTestSupport.NewMockVerifiedPermissionsHTTPClient()

	options := awscommon.AWSClientOptions{
		HTTPClient:   mockClient,
		DisableRetry: true,
	}
	nameMap := make(map[string]string, 2)
	nameMap["username"] = "account"
	nameMap["a"] = "123"
	info := avpTestSupport.IntegrationInfo()
	integration, err := OpenIntegration(WithIntegrationInfo(info), WithProviderOptions(options), WithAttributeMap(nameMap))
	assert.NoError(t, err, "Check no error opening mock provider")

	switch prov := integration.provider.(type) {
	case *avpProvider.AmazonAvpProvider:
		cedarMapper := prov.CedarMapper
		assert.NotNil(t, cedarMapper)
		res := cedarMapper.ConditionMapper.NameMapper.GetProviderAttributeName("a")
		assert.Equal(t, "123", res)
	default:
		assert.Fail(t, "Expecting an Amazon AVP Provider!")
	}
}
