package sdk

import (
    "net/http"

    "github.com/hexa-org/policy-mapper/api/policyprovider"
)

type Options struct {
    // The HTTP client to invoke API calls with. Defaults to client's default HTTP
    // implementation if nil.
    HTTPClient http.Client                     `json:"-"`
    Info       *policyprovider.IntegrationInfo `json:"integrationInfo"`

    ProviderOpts interface{} `json:"-"`
}

func WithHttpClient(client http.Client) func(*Options) {
    return func(o *Options) {
        o.HTTPClient = client
    }
}

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
