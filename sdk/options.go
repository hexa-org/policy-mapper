package sdk

import (
	"github.com/hexa-org/policy-mapper/api/policyprovider"
)

type Options struct {
	// The HTTP client to invoke API calls with. Defaults to client's default HTTP
	// implementation if nil.
	HTTPClient   interface{}                     `json:"-"`
	Info         *policyprovider.IntegrationInfo `json:"integrationInfo"`
	AttributeMap map[string]string
	ProviderOpts interface{} `json:"-"`
}

func WithHttpClient(client interface{}) func(*Options) {
	return func(o *Options) {
		o.HTTPClient = client
	}
}

// WithProviderOptions allows provider specific options to be passed through to the provider on initialization
// For example, AWS AVP Provider supports #awscommon.AWSClientOptions
func WithProviderOptions(options interface{}) func(*Options) {
	return func(o *Options) {
		o.ProviderOpts = options
	}
}

func WithIntegrationInfo(info policyprovider.IntegrationInfo) func(options *Options) {
	return func(o *Options) {
		o.Info = &info
	}
}

// WithAttributeMap may be used with providers that support IDQL conditions. The nameMap value indicates how an IDQL
// attribute name is mapped to the target attr
// ibute name.  For example username maps to account.  The map is of the form
// map['<scimName>'] = "<platformName>"
func WithAttributeMap(nameMap map[string]string) func(options *Options) {
	return func(o *Options) {
		o.AttributeMap = nameMap
	}
}
