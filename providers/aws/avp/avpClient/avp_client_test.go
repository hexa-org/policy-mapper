package avpClient

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"
	"github.com/hexa-org/policy-mapper/api/PolicyProvider"
	"github.com/hexa-org/policy-mapper/providers/aws/awscommon"
	"github.com/stretchr/testify/assert"
)

type TestInfo struct {
	Apps          []PolicyProvider.ApplicationInfo
	AwsClientOpts awscommon.AWSClientOptions
	Info          PolicyProvider.IntegrationInfo
	Client        *verifiedpermissions.Client
}

var testData TestInfo
var initialized = false

func initializeTests() error {
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

	info := PolicyProvider.IntegrationInfo{Name: "avp", Key: []byte(str)}

	testData = TestInfo{
		AwsClientOpts: awscommon.AWSClientOptions{DisableRetry: true},
		Info:          info,
	}

	client := verifiedpermissions.NewFromConfig(cfg)
	testData.Client = client
	initialized = true
	return nil
}

func TestNewAvpClient(t *testing.T) {
	initializeTests()
	client, err := NewAvpClient(testData.Info.Key, testData.AwsClientOpts)
	assert.NoError(t, err, "NewAVPClient had no error")
	assert.NotNil(t, client, "avp client returned")
}

func Test_avpClient_CreatePolicy(t *testing.T) {
	initializeTests()

	type fields struct {
		client *verifiedpermissions.Client
		app    PolicyProvider.ApplicationInfo
	}
	type args struct {
		createPolicyInput *verifiedpermissions.CreatePolicyInput
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *verifiedpermissions.CreatePolicyOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &avpClient{
				client: tt.fields.client,
				app:    tt.fields.app,
			}
			got, err := c.CreatePolicy(tt.args.createPolicyInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreatePolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreatePolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_avpClient_DeletePolicy(t *testing.T) {
	type fields struct {
		client *verifiedpermissions.Client
		app    PolicyProvider.ApplicationInfo
	}
	type args struct {
		deletePolicyInput *verifiedpermissions.DeletePolicyInput
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *verifiedpermissions.DeletePolicyOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &avpClient{
				client: tt.fields.client,
				app:    tt.fields.app,
			}
			got, err := c.DeletePolicy(tt.args.deletePolicyInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeletePolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DeletePolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_avpClient_GetPolicy(t *testing.T) {
	type fields struct {
		client *verifiedpermissions.Client
		app    PolicyProvider.ApplicationInfo
	}
	type args struct {
		id  *string
		app PolicyProvider.ApplicationInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *verifiedpermissions.GetPolicyOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &avpClient{
				client: tt.fields.client,
				app:    tt.fields.app,
			}
			got, err := c.GetPolicy(tt.args.id, tt.args.app)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_avpClient_GetTemplatePolicy(t *testing.T) {
	type fields struct {
		client *verifiedpermissions.Client
		app    PolicyProvider.ApplicationInfo
	}
	type args struct {
		id  *string
		app PolicyProvider.ApplicationInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *verifiedpermissions.GetPolicyTemplateOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &avpClient{
				client: tt.fields.client,
				app:    tt.fields.app,
			}
			got, err := c.GetTemplatePolicy(tt.args.id, tt.args.app)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTemplatePolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetTemplatePolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_avpClient_ListPolicies(t *testing.T) {
	type fields struct {
		client *verifiedpermissions.Client
		app    PolicyProvider.ApplicationInfo
	}
	type args struct {
		app PolicyProvider.ApplicationInfo
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []types.PolicyItem
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &avpClient{
				client: tt.fields.client,
				app:    tt.fields.app,
			}
			got, err := c.ListPolicies(tt.args.app)
			if (err != nil) != tt.wantErr {
				t.Errorf("ListPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListPolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_avpClient_ListStores(t *testing.T) {
	type fields struct {
		client *verifiedpermissions.Client
		app    PolicyProvider.ApplicationInfo
	}
	tests := []struct {
		name     string
		fields   fields
		wantApps []PolicyProvider.ApplicationInfo
		wantErr  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &avpClient{
				client: tt.fields.client,
				app:    tt.fields.app,
			}
			gotApps, err := c.ListStores()
			if (err != nil) != tt.wantErr {
				t.Errorf("ListStores() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotApps, tt.wantApps) {
				t.Errorf("ListStores() gotApps = %v, want %v", gotApps, tt.wantApps)
			}
		})
	}
}

func Test_avpClient_UpdatePolicy(t *testing.T) {
	type fields struct {
		client *verifiedpermissions.Client
		app    PolicyProvider.ApplicationInfo
	}
	type args struct {
		updatePolicy *verifiedpermissions.UpdatePolicyInput
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *verifiedpermissions.UpdatePolicyOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &avpClient{
				client: tt.fields.client,
				app:    tt.fields.app,
			}
			got, err := c.UpdatePolicy(tt.args.updatePolicy)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdatePolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UpdatePolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newAvpClient(t *testing.T) {
	type args struct {
		key  []byte
		opts awscommon.AWSClientOptions
	}
	tests := []struct {
		name    string
		args    args
		want    *verifiedpermissions.Client
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newAvpClient(tt.args.key, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("newAvpClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newAvpClient() got = %v, want %v", got, tt.want)
			}
		})
	}
}
