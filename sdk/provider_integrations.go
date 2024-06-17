package sdk

import (
    "errors"
    "fmt"
    "net/http"
    "os"

    "github.com/hexa-org/policy-mapper/api/policyprovider"
    "github.com/hexa-org/policy-mapper/models/formats/awsCedar"
    "github.com/hexa-org/policy-mapper/models/formats/gcpBind"
    "github.com/hexa-org/policy-mapper/providers/aws/avpProvider"
    "github.com/hexa-org/policy-mapper/providers/aws/awsapigwProvider"
    "github.com/hexa-org/policy-mapper/providers/aws/awscommon"
    "github.com/hexa-org/policy-mapper/providers/aws/cognitoProvider"
    "github.com/hexa-org/policy-mapper/providers/azure/azureProvider"
    "github.com/hexa-org/policy-mapper/providers/googlecloud/iapProvider"
    "github.com/hexa-org/policy-mapper/providers/openpolicyagent"
    "github.com/hexa-org/policy-mapper/providers/test"
)

/*
Open causes the provider to be instantiated and a handle to the Provider interface is returned. Note: providers
are automatically opened if Open is not called. Primary purpose is to expose the underlying Provider interface for
some integrations such as policyprovider.
*/
func (i *Integration) open() error {
    if i.provider != nil {
        return nil
    }
    testOverride := os.Getenv(EnvTestProvider)
    info := i.Opts.Info
    if info == nil {
        return errors.New("missing PolicyProvider.IntegrationInfo object")
    }
    provType := info.Name
    if testOverride != "" {
        fmt.Println("Overriding " + provType + " with " + testOverride)
        provType = testOverride
    }
    var err error
    switch provType {
    case ProviderTypeAvp:
        i.provider, err = newAvpProvider(i.Opts)
        return err

    case ProviderTypeCognito:
        i.provider, err = newCognitoProvider(i.Opts)
        return err

    case ProviderTypeAwsApiGW:
        i.provider, err = newAwsApiGWProvider(i.Opts)
        return err

    case ProviderTypeAzure:
        i.provider, err = newAzureProvider(i.Opts)
        return err

    case ProviderTypeGoogleCloudLegacy, ProviderTypeGoogleCloudIAP:
        i.provider, err = newGoogleProvider(i.Opts)
        return err

    case ProviderTypeOpa:
        i.provider, err = newOpaProvider(i.Opts)
        return err

    case ProviderTypeMock:
        i.provider = &test.MockProvider{
            Info: *i.Opts.Info,
        }
        return nil
    default:
        return errors.New("provider not available in hexa policy SDK")
    }
}

func newAzureProvider(options Options) (policyprovider.Provider, error) {
    var ret *azureProvider.AzureProvider
    if options.ProviderOpts != nil {
        switch v := options.ProviderOpts.(type) {
        case azureProvider.ProviderOpt:
            ret = azureProvider.NewAzureProvider(v)

        default:
            fmt.Println("Warning, unexpected ProviderOpts (use awscommon.AWSClientOptions)")
        }
    }
    if ret == nil {
        ret = azureProvider.NewAzureProvider(nil)
    }
    return ret, nil
}

func newAwsApiGWProvider(options Options) (policyprovider.Provider, error) {
    var ret *awsapigwProvider.AwsApiGatewayProvider
    if options.ProviderOpts != nil {
        switch v := options.ProviderOpts.(type) {
        case awsapigwProvider.AwsApiGatewayProviderOpt:
            ret = awsapigwProvider.NewAwsApiGatewayProvider(v)

        default:
            fmt.Println("Warning, unexpected ProviderOpts (use awscommon.AWSClientOptions)")
        }
    }
    if ret == nil {
        ret = awsapigwProvider.NewAwsApiGatewayProvider()
    }
    return ret, nil
}

func newCognitoProvider(options Options) (policyprovider.Provider, error) {
    opts := awscommon.AWSClientOptions{DisableRetry: true}
    if options.HTTPClient != nil {
        switch client := options.HTTPClient.(type) {
        case awscommon.AWSHttpClient:
            opts.HTTPClient = client
        default:
            return nil, errors.New("HTTPClient type supported, use WithHttpClient(awscommon.AWSHttpClient)")
        }

    }
    if options.ProviderOpts != nil {
        switch v := options.ProviderOpts.(type) {
        case awscommon.AWSClientOptions:
            if opts.HTTPClient != nil {
                override := opts.HTTPClient
                opts = v
                opts.HTTPClient = override
            } else {
                opts = v
            }
        default:
            fmt.Println("Warning, unexpected ProviderOpts (use awscommon.AWSClientOptions)")
        }
    }

    return &cognitoProvider.CognitoProvider{
        AwsClientOpts: opts,
    }, nil
}

func newAvpProvider(options Options) (policyprovider.Provider, error) {
    opts := awscommon.AWSClientOptions{DisableRetry: true}
    if options.HTTPClient != nil {
        switch client := options.HTTPClient.(type) {
        case awscommon.AWSHttpClient:
            opts.HTTPClient = client
        default:
            return nil, errors.New("HTTPClient type supported, use WithHttpClient(awscommon.AWSHttpClient)")
        }

    }
    if options.ProviderOpts != nil {
        switch v := options.ProviderOpts.(type) {
        case awscommon.AWSClientOptions:
            if opts.HTTPClient != nil {
                override := opts.HTTPClient
                opts = v
                opts.HTTPClient = override
            } else {
                opts = v
            }
        default:
            fmt.Println("Warning, unexpected ProviderOpts (use awscommon.AWSClientOptions)")
        }
    }
    var mapper *awsCedar.CedarPolicyMapper
    if options.AttributeMap != nil {
        mapper = awsCedar.New(options.AttributeMap)
    } else {
        mapper = awsCedar.New(map[string]string{})
    }

    return &avpProvider.AmazonAvpProvider{
        AwsClientOpts: opts,
        CedarMapper:   mapper,
    }, nil
}

func newGoogleProvider(options Options) (policyprovider.Provider, error) {

    if options.ProviderOpts != nil {
        return nil, errors.New("provider options not currently supported for " + ProviderTypeGoogleCloudIAP)
    }

    var httpClient iapProvider.HTTPClient
    if options.HTTPClient != nil {
        switch client := options.HTTPClient.(type) {
        case iapProvider.HTTPClient:

            httpClient = client
        default:
            return nil, errors.New("HTTPClient type supported, use WithHttpClient(awscommon.AWSHttpClient)")
        }

    }
    var mapper *gcpBind.GooglePolicyMapper
    if options.AttributeMap != nil {
        mapper = gcpBind.New(options.AttributeMap)
    } else {
        mapper = gcpBind.New(map[string]string{})
    }

    return &iapProvider.GoogleProvider{
        HttpClientOverride: httpClient,
        GcpMapper:          mapper,
    }, nil
}

func newOpaProvider(options Options) (policyprovider.Provider, error) {

    // TODO: Implement bundle client options (see tests)
    if options.ProviderOpts != nil {
        return nil, errors.New("provider options not currently supported for " + ProviderTypeOpa)
    }

    if options.HTTPClient != nil {
        switch client := options.HTTPClient.(type) {
        case http.Client:
            return &openpolicyagent.OpaProvider{HttpClient: &client}, nil
        case *http.Client:
            return &openpolicyagent.OpaProvider{HttpClient: client}, nil
        }
        return nil, errors.New("HTTPClient type supported, use WithHttpClient(http.Client{})")
    }

    return &openpolicyagent.OpaProvider{}, nil
}
