package sdk

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/providers/openpolicyagent"
)

type Options struct {
	// The HTTP client to invoke API calls with. Defaults to client's default HTTP
	// implementation if nil.
	HTTPClient   interface{}                     `json:"-"`
	Info         *policyprovider.IntegrationInfo `json:"integrationInfo"`
	AttributeMap map[string]string
	ProviderOpts interface{} `json:"-"`
}

// WithIntegrationInfo provides a previously defined policyprovider.IntegrationInfo object to
// configure an integration.
func WithIntegrationInfo(info policyprovider.IntegrationInfo) func(*Options) {
	return func(o *Options) {
		o.Info = &info
	}
}

// WithProviderOptions allows provider specific options to be passed through to the provider on initialization
// For example, AWS AVP Provider supports #awscommon.AWSClientOptions
func WithProviderOptions(options interface{}) func(*Options) {
	return func(o *Options) {
		o.ProviderOpts = options
	}
}

// WithAttributeMap may be used with providers that support IDQL conditions. The nameMap value indicates how an IDQL
// attribute name is mapped to the target attribute name.  For example username maps to account.  The map is of the form
// map['<scimName>'] = "<platformName>"
// Currently supported by syntactic mappers such as AVP Provider and GCP IAP Provider
func WithAttributeMap(nameMap map[string]string) func(options *Options) {
	return func(o *Options) {
		o.AttributeMap = nameMap
	}
}

// WithOpaGcpIntegration is a convenience method to build up an integration to initialize the OPA provider with GCP as the
// bucket repository. This method overrides information provided with the IntegrationInfo parameter of OpenIntegration
func WithOpaGcpIntegration(bucketName string, objectName string, credentialKey []byte) func(options *Options) {
	return func(o *Options) {
		gcpCredKey := json.RawMessage(credentialKey)
		credential := openpolicyagent.Credentials{

			GCP: &openpolicyagent.GcpCredentials{
				BucketName: bucketName,
				ObjectName: objectName,
				Key:        gcpCredKey,
			},
		}
		key, _ := json.Marshal(&credential)

		o.Info = &policyprovider.IntegrationInfo{
			Name: ProviderTypeOpa,
			Key:  key,
		}
	}
}

// WithOpaAwsIntegration is a convenience method to build up an integration to initialize the OPA provider with AWS S3 as the
// bucket repository. This method overrides information provided with the IntegrationInfo parameter of OpenIntegration
func WithOpaAwsIntegration(bucketName string, objectName string, credentialKey []byte) func(options *Options) {
	return func(o *Options) {
		credKey := json.RawMessage(credentialKey)
		credential := openpolicyagent.Credentials{
			AWS: &openpolicyagent.AwsCredentials{
				BucketName: bucketName,
				ObjectName: objectName,
				Key:        credKey,
			},
		}
		key, _ := json.Marshal(&credential)

		o.Info = &policyprovider.IntegrationInfo{
			Name: ProviderTypeOpa,
			Key:  key,
		}
	}
}

// WithOpaGithubIntegration is a convenience method to build up an integration to initialize the OPA provider with a GitHub repository as the
// bucket repository. This method overrides information provided with the IntegrationInfo parameter of OpenIntegration
func WithOpaGithubIntegration(account string, repo string, bundlePath string, token []byte) func(options *Options) {
	return func(o *Options) {
		credential := openpolicyagent.Credentials{
			GITHUB: &openpolicyagent.GithubCredentials{
				Account:    account,
				Repo:       repo,
				BundlePath: bundlePath,
				Key:        token,
			},
		}
		key, _ := json.Marshal(&credential)

		o.Info = &policyprovider.IntegrationInfo{
			Name: ProviderTypeOpa,
			Key:  key,
		}
	}
}

// WithOpaHttpIntegration is a convenience method to build up an integration to initialize the OPA provider with an HTTP service as the
// bucket repository. This method overrides information provided with the IntegrationInfo parameter of OpenIntegration
// The HTTP service must support GET and POST (Form) to retrieve and replace OPA bundles.
func WithOpaHttpIntegration(bundleUrl string, caCert string, token *string) func(options *Options) {

	bURL, err := url.Parse(bundleUrl)
	targetUrl := bundleUrl
	if err == nil && bURL.Path == "" {
		bURL.Path = "/bundles/bundle.tar.gz"
		fmt.Println(fmt.Sprintf("Defaulting bundle path to: %s", bURL.String()))
		targetUrl = bURL.String()
	}
	auth := ""
	if token != nil && len(*token) > 7 {
		auth = *token
		if strings.ToLower(auth)[0:7] != "bearer " {
			auth = "Bearer " + auth
		}
	}
	return func(o *Options) {
		credential := openpolicyagent.Credentials{
			BundleUrl:     targetUrl,
			CACert:        caCert,
			Authorization: auth,
		}
		key, _ := json.Marshal(&credential)

		o.Info = &policyprovider.IntegrationInfo{
			Name: ProviderTypeOpa,
			Key:  key,
		}
	}
}
