package avpTestSupport

import (
	"fmt"

	"github.com/hexa-org/policy-mapper/api/PolicyProvider"
)

const TestAwsRegion = "us-west-1"
const TestAwsAccessKeyId = "anAccessKeyID"
const TestAwsSecretAccessKey = "aSecretAccessKey"

const TestPolicyStoreArn = "arn:aws:verifiedpermissions::773752081234:policy-store/K21RFtXLb2qPRGA93DH7z5"

var TestPolicyStoreId = "K21RFtXLb2qPRGA93DH7z5"

const TestPolicyStoreDescription = "Test Policy Store"
const TestResourceServerIdentifier = "https://some-resource-server"

var TestCedarStaticPolicyDescription = "Simple static policy"
var TestCedarStaticPolicy = `
permit(
  principal,
  action in [hexa_avp::Action::"ReadAccount",hexa_avp::Action::"Transfer",hexa_avp::Action::"Deposit",hexa_avp::Action::"Withdrawl"],
  resource
);`
var TestCedarStaticPolicyId = "id1"

var TestCedarTemplatePolicy = `
permit(
    principal == ?principal,
    action in [hexa_avp::Action::"ReadAccount"],
    resource == ?resource
);`
var TestCedarTemplatePolicyId = "id2"
var TestCedarTemplateId = "temp1"

// const TestResourceServerName = "some-resource-server-name"

func AwsCredentialsForTest() []byte {
	str := fmt.Sprintf(`
{
  "accessKeyID": "%s",
  "secretAccessKey": "%s",
  "region": "%s"
}
`, TestAwsAccessKeyId, TestAwsSecretAccessKey, TestAwsRegion)

	return []byte(str)
}

func IntegrationInfo() PolicyProvider.IntegrationInfo {
	return PolicyProvider.IntegrationInfo{Name: "avp", Key: AwsCredentialsForTest()}
}

func AppInfo() PolicyProvider.ApplicationInfo {
	return PolicyProvider.ApplicationInfo{
		ObjectID:    TestPolicyStoreId,
		Name:        "Test Policy Store",
		Description: "AVP Mock Test",
		Service:     TestResourceServerIdentifier,
	}
}
