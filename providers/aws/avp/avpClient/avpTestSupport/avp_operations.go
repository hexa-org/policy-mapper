package avpTestSupport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

var AvpApiUrl = fmt.Sprintf("https://verifiedpermissions.%s.amazonaws.com/", TestAwsRegion)

func (m *MockVerifiedPermissionsHTTPClient) MockListStores() {
	m.MockListStoresWithHttpStatus(http.StatusOK)
}

func (m *MockVerifiedPermissionsHTTPClient) MockListStoresWithHttpStatus(httpStatus int) {
	m.AddRequest(http.MethodPost, AvpApiUrl, "ListPolicyStores", httpStatus, ListStoresResponse())
}

type MockPolicyStoresOutput struct {
	// The parser in AWS verified permissions client is looking for "policyStores"
	PolicyStores []MockPolicyStoreItem `json:"policyStores"`
	NextToken    *string               `json:"nextToken"`
}

type MockPolicyStoreItem struct {
	Arn             *string    `json:"arn"`
	PolicyStoreId   *string    `json:"policyStoreId"`
	CreatedDate     *time.Time `json:"createdDate"`
	LastUpdatedDate *time.Time `json:"lastUpdatedDate"`
	Description     *string    `json:"description"`
}

func ListStoresResponse() []byte {
	policyDate := time.Date(2023, 12, 1, 1, 2, 3, 0, time.UTC)
	output := MockPolicyStoresOutput{
		PolicyStores: []MockPolicyStoreItem{
			{
				Arn:             aws.String(TestPolicyStoreArn),
				PolicyStoreId:   aws.String(TestPolicyStoreId),
				CreatedDate:     &policyDate,
				LastUpdatedDate: &policyDate,
				Description:     aws.String(TestPolicyStoreDescription),
			},
		},
		NextToken: nil,
	}

	outBytes, _ := json.Marshal(output)
	return outBytes
}

type EntityIdentifier struct {

	// The identifier of an entity.
	//
	// "entityId":"identifier"
	//
	// EntityId is a sensitive parameter and its value will be
	// replaced with "sensitive" in string returned by EntityIdentifier's
	// String and GoString methods.
	//
	// EntityId is a required field
	EntityId *string `json:"entityId" locationName:"entityId" min:"1" type:"string" required:"true" sensitive:"true"`

	// The type of an entity.
	//
	// Example: "entityType":"typeName"
	//
	// EntityType is a sensitive parameter and its value will be
	// replaced with "sensitive" in string returned by EntityIdentifier's
	// String and GoString methods.
	//
	// EntityType is a required field
	EntityType *string `json:"entityType" locationName:"entityType" min:"1" type:"string" required:"true" sensitive:"true"`
	// contains filtered or unexported fields
}

type StaticPolicyDefinitionItem struct {

	// A description of the static policy.
	//
	// Description is a sensitive parameter and its value will be
	// replaced with "sensitive" in string returned by StaticPolicyDefinitionItem's
	// String and GoString methods.
	Description *string `json:"description" locationName:"description" type:"string" sensitive:"true"`
	// contains filtered or unexported fields

	// Statement is a required field
	Statement *string `json:"statement" locationName:"statement" min:"1" type:"string" required:"true" sensitive:"true"`
	// contains filtered or unexported fields
}

type TemplateLinkedPolicyDefinitionItem struct {

	// The unique identifier of the policy template used to create this policy.
	//
	// PolicyTemplateId is a required field
	PolicyTemplateId *string `json:"policyTemplateId" locationName:"policyTemplateId" min:"1" type:"string" required:"true"`

	// The principal associated with this template-linked policy. Verified Permissions
	// substitutes this principal for the ?principal placeholder in the policy template
	// when it evaluates an authorization request.
	Principal *EntityIdentifier `json:"principal" locationName:"principal" type:"structure"`

	// The resource associated with this template-linked policy. Verified Permissions
	// substitutes this resource for the ?resource placeholder in the policy template
	// when it evaluates an authorization request.
	Resource *EntityIdentifier `json:"resource" locationName:"resource" type:"structure"`
	// contains filtered or unexported fields
}

type PolicyDefinitionItem struct {

	// Information about a static policy that wasn't created with a policy template.
	Static *StaticPolicyDefinitionItem `json:"static" locationName:"static" type:"structure"`

	// Information about a template-linked policy that was created by instantiating
	// a policy template.
	TemplateLinked *TemplateLinkedPolicyDefinitionItem `json:"templateLinked" locationName:"templateLinked" type:"structure"`
	// contains filtered or unexported fields
}

type PolicyItem struct {
	// The date and time the policy was created.
	//
	// CreatedDate is a required field
	CreatedDate *time.Time `json:"createdDate" locationName:"createdDate" type:"timestamp" timestampFormat:"iso8601" required:"true"`

	// The policy definition of an item in the list of policies returned.
	//
	// Definition is a required field
	Definition *PolicyDefinitionItem `json:"definition" locationName:"definition" type:"structure" required:"true"`

	// The date and time the policy was most recently updated.
	//
	// LastUpdatedDate is a required field
	LastUpdatedDate *time.Time `json:"lastUpdatedDate" locationName:"lastUpdatedDate" type:"timestamp" timestampFormat:"iso8601" required:"true"`

	// The identifier of the policy you want information about.
	//
	// PolicyId is a required field
	PolicyId *string `json:"policyId" locationName:"policyId" min:"1" type:"string" required:"true"`

	// The identifier of the PolicyStore where the policy you want information about
	// is stored.
	//
	// PolicyStoreId is a required field
	PolicyStoreId *string `json:"policyStoreId" locationName:"policyStoreId" min:"1" type:"string" required:"true"`

	// The type of the policy. This is one of the following values:
	//
	//    * static
	//
	//    * templateLinked
	//
	// PolicyType is a required field
	PolicyType *string `json:"policyType" locationName:"policyType" type:"string" required:"true" enum:"PolicyType"`

	// The principal associated with the policy.
	Principal *EntityIdentifier `json:"principal" locationName:"principal" type:"structure"`

	// The resource associated with the policy.
	Resource *EntityIdentifier `json:"resource" locationName:"resource" type:"structure"`
	// contains filtered or unexported fields
}

type GetPolicyTemplateOutput struct {

	// The date and time that the policy template was originally created.
	//
	// CreatedDate is a required field
	CreatedDate *time.Time `json:"createdDate" locationName:"createdDate" type:"timestamp" timestampFormat:"iso8601" required:"true"`

	// The description of the policy template.
	//
	// Description is a sensitive parameter and its value will be
	// replaced with "sensitive" in string returned by GetPolicyTemplateOutput's
	// String and GoString methods.
	Description *string `json:"description" locationName:"description" type:"string" sensitive:"true"`

	// The date and time that the policy template was most recently updated.
	//
	// LastUpdatedDate is a required field
	LastUpdatedDate *time.Time `json:"lastUpdatedDate" locationName:"lastUpdatedDate" type:"timestamp" timestampFormat:"iso8601" required:"true"`

	// The ID of the policy store that contains the policy template.
	//
	// PolicyStoreId is a required field
	PolicyStoreId *string `json:"policyStoreId" locationName:"policyStoreId" min:"1" type:"string" required:"true"`

	// The ID of the policy template.
	//
	// PolicyTemplateId is a required field
	PolicyTemplateId *string `json:"policyTemplateId" locationName:"policyTemplateId" min:"1" type:"string" required:"true"`

	// The content of the body of the policy template written in the Cedar policy
	// language.
	//
	// Statement is a sensitive parameter and its value will be
	// replaced with "sensitive" in string returned by GetPolicyTemplateOutput's
	// String and GoString methods.
	//
	// Statement is a required field
	Statement *string `json:"statement" locationName:"statement" min:"1" type:"string" required:"true" sensitive:"true"`
	// contains filtered or unexported fields
}

type MockListPoliciesOutput struct {
	Policies  []PolicyItem `json:"policies"`
	NextToken *string      `json:"nextToken"`
}

func GenerateStaticPolicyItem(isDetail bool, id string) PolicyItem {
	testDate := time.Date(2023, 12, 1, 1, 2, 3, 0, time.UTC)

	var staticItem StaticPolicyDefinitionItem

	staticItem = StaticPolicyDefinitionItem{
		Description: &TestCedarStaticPolicyDescription,
	}
	if isDetail {
		staticItem.Statement = &TestCedarStaticPolicy
	}
	staticDefinition := PolicyDefinitionItem{Static: &staticItem}

	policyType := "STATIC"

	return PolicyItem{
		CreatedDate:     &testDate,
		LastUpdatedDate: &testDate,
		Principal:       nil,
		Resource:        nil,
		Definition:      &staticDefinition,
		PolicyStoreId:   &TestPolicyStoreId,
		PolicyType:      &policyType,
		PolicyId:        &id,
	}
}

func GenerateTemplatePolicyItem(id string) PolicyItem {
	testDate := time.Date(2022, 12, 1, 1, 2, 3, 0, time.UTC)

	princId := "joe@example.com"
	princType := "hexa_avp::User"
	principleIdentifier := EntityIdentifier{
		EntityId:   &princId,
		EntityType: &princType,
	}
	resId := "1"
	resType := "hexa_avp::account"
	resourceIdentifier := EntityIdentifier{
		EntityId:   &resId,
		EntityType: &resType,
	}
	templateItem := TemplateLinkedPolicyDefinitionItem{
		PolicyTemplateId: &TestCedarTemplateId,
		Principal:        &principleIdentifier,
		Resource:         &resourceIdentifier,
	}
	templateDefinition := PolicyDefinitionItem{TemplateLinked: &templateItem}
	policyType := "TEMPLATE_LINKED" // types.PolicyTypeTemplateLinked
	return PolicyItem{
		CreatedDate:     &testDate,
		LastUpdatedDate: &testDate,
		Principal:       nil,
		Resource:        nil,
		Definition:      &templateDefinition,
		PolicyStoreId:   &TestPolicyStoreId,
		PolicyId:        &id,
		PolicyType:      &policyType,
	}
}

func (m *MockVerifiedPermissionsHTTPClient) MockGetPolicyTemplateWithHttpStatus(httpStatus int, id string) {
	m.AddRequest(http.MethodPost, AvpApiUrl, "GetPolicyTemplate", httpStatus, GetPolicyTemplateResponse(id))
}

func GetPolicyTemplateResponse(id string) []byte {
	testDate := time.Date(2023, 2, 1, 1, 2, 3, 0, time.UTC)
	description := "Test Hexa Policy Template"
	policy := GetPolicyTemplateOutput{
		CreatedDate:      &testDate,
		Description:      &description,
		LastUpdatedDate:  &testDate,
		PolicyStoreId:    &TestPolicyStoreId,
		PolicyTemplateId: &id,
		Statement:        &TestCedarTemplatePolicy,
	}
	outBytes, _ := json.Marshal(policy)
	return outBytes
}

func (m *MockVerifiedPermissionsHTTPClient) MockGetPolicyWithHttpStatus(httpStatus int, id string) {
	m.AddRequest(http.MethodPost, AvpApiUrl, "GetPolicy", httpStatus, GetPolicyResponse(id))
}

func GetPolicyResponse(id string) []byte {
	policyItem := GenerateStaticPolicyItem(true, id)

	outBytes, _ := json.Marshal(policyItem)
	return outBytes
}

func (m *MockVerifiedPermissionsHTTPClient) MockListPolicies() {
	m.MockListPoliciesWithHttpStatus(http.StatusOK, 1, 1, nil)
}

func (m *MockVerifiedPermissionsHTTPClient) MockListPoliciesWithHttpStatus(httpStatus int, staticPolCnt int, templatePolCnt int, nextToken *string) {
	if httpStatus != 200 {
		m.AddRequest(http.MethodPost, AvpApiUrl, "ListPolicies", httpStatus, []byte{})
		return
	}
	m.AddRequest(http.MethodPost, AvpApiUrl, "ListPolicies", httpStatus, ListPoliciesResponse(staticPolCnt, templatePolCnt, nextToken))
}

func ListPoliciesResponse(staticPolCnt int, templatePolCnt int, nextToken *string) []byte {

	var policies = make([]PolicyItem, 0)
	statCnt := 0
	templCnt := 0

	i := 0
	if nextToken != nil {
		i, _ = strconv.Atoi(*nextToken)
	}
	for ; (statCnt+templCnt < 50) && ((statCnt < staticPolCnt) || (templCnt < templatePolCnt)); i++ {
		if statCnt < staticPolCnt {
			statCnt++
			policies = append(policies, GenerateStaticPolicyItem(false, TestCedarStaticPolicyId+strconv.Itoa(i)))
		}

		if templCnt < templatePolCnt {
			templCnt++
			policies = append(policies, GenerateTemplatePolicyItem(TestCedarTemplatePolicyId+strconv.Itoa(i)))
		}
	}

	nextToken = nil // Set to nil if no more results
	if templCnt+statCnt >= 50 {
		index := strconv.Itoa(i)
		nextToken = &index
	}
	output := MockListPoliciesOutput{
		Policies:  policies,
		NextToken: nextToken,
	}

	outBytes, _ := json.Marshal(output)
	return outBytes
}
