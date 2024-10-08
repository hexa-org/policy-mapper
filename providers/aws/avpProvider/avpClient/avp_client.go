package avpClient

import (
    "context"
    "fmt"

    "github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
    "github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"
    "github.com/hexa-org/policy-mapper/api/policyprovider"
    "github.com/hexa-org/policy-mapper/providers/aws/awscommon"
)

type AvpClient interface {
    ListStores() (apps []policyprovider.ApplicationInfo, err error)
    ListPolicies(app policyprovider.ApplicationInfo) ([]types.PolicyItem, error)
    GetTemplatePolicy(id string, app policyprovider.ApplicationInfo) (*verifiedpermissions.GetPolicyTemplateOutput, error)
    GetPolicy(id string, app policyprovider.ApplicationInfo) (*verifiedpermissions.GetPolicyOutput, error)
    CreatePolicy(createPolicyInput *verifiedpermissions.CreatePolicyInput) (*verifiedpermissions.CreatePolicyOutput, error)
    UpdatePolicy(updatePolicy *verifiedpermissions.UpdatePolicyInput) (*verifiedpermissions.UpdatePolicyOutput, error)
    DeletePolicy(deletePolicyInput *verifiedpermissions.DeletePolicyInput) (*verifiedpermissions.DeletePolicyOutput, error)
    GetSchema(app policyprovider.ApplicationInfo) (*verifiedpermissions.GetSchemaOutput, error)
    PutSchema(app policyprovider.ApplicationInfo, schema types.SchemaDefinition) (*verifiedpermissions.PutSchemaOutput, error)
}

type avpClient struct {
    client *verifiedpermissions.Client
    app    policyprovider.ApplicationInfo
}

func NewAvpClient(key []byte, opt awscommon.AWSClientOptions) (AvpClient, error) {
    client, err := newAvpClient(key, opt)
    if err != nil {
        return nil, err
    }
    return &avpClient{client: client}, nil
}

func newAvpClient(key []byte, opts awscommon.AWSClientOptions) (*verifiedpermissions.Client, error) {
    cfg, err := awscommon.GetAwsClientConfig(key, opts)
    if err != nil {
        return nil, err
    }

    return verifiedpermissions.NewFromConfig(cfg), nil
}

func (c *avpClient) ListStores() (apps []policyprovider.ApplicationInfo, err error) {
    maxRes := int32(50) // Maximum allowed is 50 per page
    storesInput := verifiedpermissions.ListPolicyStoresInput{
        MaxResults: &maxRes,
    }
    storeOutput, err := c.client.ListPolicyStores(context.Background(), &storesInput)
    if err != nil {
        return nil, err
    }

    for _, storeItem := range storeOutput.PolicyStores {
        apps = append(apps, policyprovider.ApplicationInfo{
            ObjectID:    *storeItem.PolicyStoreId,
            Name:        *storeItem.Arn,
            Description: *storeItem.Description,
            Service:     "VerifiedPermissions",
        })
    }
    return apps, nil
}

// ListPolicies calls avp and collects all the policies found and does paging if necessary
func (c *avpClient) ListPolicies(app policyprovider.ApplicationInfo) ([]types.PolicyItem, error) {
    maxRes := int32(50) // Maximum is 50?
    policyInput := verifiedpermissions.ListPoliciesInput{
        PolicyStoreId: &app.ObjectID,
        MaxResults:    &maxRes,
    }
    morePage := true
    var policies []types.PolicyItem
    for morePage == true {
        policyOutput, err := c.client.ListPolicies(context.Background(), &policyInput)
        if err != nil {
            return nil, err
        }
        for _, v := range policyOutput.Policies {
            policies = append(policies, v)
        }
        if policyOutput.NextToken != nil {
            fmt.Println("  paging policies...")
            policyInput.NextToken = policyOutput.NextToken
        } else {
            morePage = false
        }
    }
    // fmt.Printf("%v cedar policies retrieved", len(policies))
    return policies, nil
}

func (c *avpClient) GetTemplatePolicy(id string, app policyprovider.ApplicationInfo) (*verifiedpermissions.GetPolicyTemplateOutput, error) {
    return c.client.GetPolicyTemplate(context.TODO(), &verifiedpermissions.GetPolicyTemplateInput{
        PolicyStoreId:    &app.ObjectID,
        PolicyTemplateId: &id,
    })

}

func (c *avpClient) GetPolicy(id string, app policyprovider.ApplicationInfo) (*verifiedpermissions.GetPolicyOutput, error) {
    return c.client.GetPolicy(context.TODO(), &verifiedpermissions.GetPolicyInput{
        PolicyId:      &id,
        PolicyStoreId: &app.ObjectID,
    })
}

func (c *avpClient) CreatePolicy(createPolicyInput *verifiedpermissions.CreatePolicyInput) (*verifiedpermissions.CreatePolicyOutput, error) {
    return c.client.CreatePolicy(context.TODO(), createPolicyInput)
}

func (c *avpClient) UpdatePolicy(updatePolicy *verifiedpermissions.UpdatePolicyInput) (*verifiedpermissions.UpdatePolicyOutput, error) {
    return c.client.UpdatePolicy(context.TODO(), updatePolicy)
}

func (c *avpClient) DeletePolicy(deletePolicyInput *verifiedpermissions.DeletePolicyInput) (*verifiedpermissions.DeletePolicyOutput, error) {
    return c.client.DeletePolicy(context.TODO(), deletePolicyInput)
}

func (c *avpClient) GetSchema(app policyprovider.ApplicationInfo) (*verifiedpermissions.GetSchemaOutput, error) {
    return c.client.GetSchema(context.TODO(), &verifiedpermissions.GetSchemaInput{
        PolicyStoreId: &app.ObjectID,
    })
}

func (c *avpClient) PutSchema(app policyprovider.ApplicationInfo, schema types.SchemaDefinition) (*verifiedpermissions.PutSchemaOutput, error) {
    return c.client.PutSchema(context.TODO(), &verifiedpermissions.PutSchemaInput{
        PolicyStoreId: &app.ObjectID,
        Definition:    schema,
    })
}
