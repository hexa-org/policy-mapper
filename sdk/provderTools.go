package sdk

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/hexa-org/policy-mapper/api/PolicyProvider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/providers/aws/avp"
	"github.com/hexa-org/policy-mapper/providers/aws/awscommon"
	"github.com/hexa-org/policy-mapper/providers/test"
)

const (
	ProviderTypeAvp  string = avp.ProviderTypeAvp
	ProviderTypeMock string = test.ProviderTypeMock

	EnvTestProvider string = "HEXA_TEST_PROVIDER" // EnvTestProvider overrides whatever provider is requested and uses the specified provider instead (by name)
)

type Integration struct {
	Alias    string                                    `json:"alias"`
	Opts     Options                                   `json:"options"`
	Apps     map[string]PolicyProvider.ApplicationInfo `json:"apps"`
	provider PolicyProvider.Provider                   `json:"-"`
}

/*
OpenIntegration accepts a json byte stream and parses into an IntegrationInfo which can be used to invoke the
provider features. An IntegrationInfo struct consists of:

- integrationInfo - PolicyProvider.IntegrationInfo information defining the provider type and the credential used to access. If not provided, it must be provided using Options

- options - one or more configuration functions for configuring provider See: sdk.Options
*/
func OpenIntegration(integrationInfo *PolicyProvider.IntegrationInfo, options ...func(*Options)) (*Integration, error) {

	i := &Integration{
		Opts: Options{},
	}

	if integrationInfo != nil {
		i.Opts.Info = integrationInfo
	}
	for _, opt := range options {
		opt(&i.Opts)
	}

	_, err := i.open()

	return i, err
}

/*
Open causes the provider to be instantiated and a handle to the Provider interface is returned. Note: providers
are automatically opened if Open is not called. Primary purpose is to expose the underlying Provider interface for
some integrations such as Orchestrator.
*/
func (i *Integration) open() (PolicyProvider.Provider, error) {
	if i.provider != nil {
		return i.provider, nil
	}
	testOverride := os.Getenv(EnvTestProvider)
	info := i.Opts.Info
	if info == nil {
		return nil, errors.New("missing PolicyProvider.IntegrationInfo object")
	}
	provType := info.Name
	if testOverride != "" {
		fmt.Println("Overriding " + provType + " with " + testOverride)
		provType = testOverride
	}
	switch provType {
	case ProviderTypeAvp:
		opts := awscommon.AWSClientOptions{DisableRetry: true}
		if i.Opts.ProviderOpts != nil {
			switch v := i.Opts.ProviderOpts.(type) {
			case awscommon.AWSClientOptions:
				opts = v
			default:
			}
		}
		i.provider = &avp.AmazonAvpProvider{AwsClientOpts: opts}

		return i.provider, nil

	case ProviderTypeMock:
		i.provider = &test.MockProvider{
			Info: *i.Opts.Info,
		}
		return i.provider, nil
	default:
		return nil, errors.New("provider not available in hexa policy SDK")
	}
}

// GetType returns the type of underlying provider. See: sdk.PROVIDER_TYPE_ values. If not defined, "ERROR" is returned.
func (i *Integration) GetType() string {
	if i.Opts.Info == nil {
		return "ERROR"
	}
	return i.Opts.Info.Name
}

func (i *Integration) checkOpen() {
	if i.provider == nil {
		_, _ = i.open()
	}
}

func (i *Integration) GetProvider() PolicyProvider.Provider {
	return i.provider
}

/*
GetPolicyApplicationPoints invokes Provider.DiscoverApplications method to locate applications or policy application
points available within a platform Integration. The 'aliasGen' func parameter is used to generate a local alias for the
application. If 'nil' is passed, the ObjectId value from ApplicationInfo is used as the alias.
*/
func (i *Integration) GetPolicyApplicationPoints(aliasGen func() string) ([]PolicyProvider.ApplicationInfo, error) {
	i.checkOpen()

	aliasMap := map[string]string{}
	if i.Apps != nil {
		for k, app := range i.Apps {
			aliasMap[app.ObjectID] = k
		}
	}
	apps, err := i.provider.DiscoverApplications(*i.Opts.Info)
	if err != nil {
		return nil, err
	}

	newAppMap := make(map[string]PolicyProvider.ApplicationInfo, len(apps))
	for _, app := range apps {
		// default to objectID
		alias := app.ObjectID

		// if the application had a previous alias, use it
		oldAlias, exist := aliasMap[app.ObjectID]
		if exist {
			alias = oldAlias
		} else {
			if aliasGen != nil {
				alias = aliasGen()
			}
		}
		newAppMap[alias] = app
	}
	i.Apps = newAppMap

	return apps, nil
}

func (i *Integration) GetApplicationInfo(papAlias string) (*PolicyProvider.ApplicationInfo, error) {
	if i.Apps == nil {
		_, err := i.GetPolicyApplicationPoints(nil)
		if err != nil {
			return nil, err
		}
	}
	info, exist := i.Apps[papAlias]
	if !exist {
		return nil, errors.New(fmt.Sprintf("alias [%s] not found", papAlias))
	}
	return &info, nil
}

/*
GetPolicies queries the designated 'pap' and returns a set of mapped hexapolicy.PolicyInfo policies.
*/
func (i *Integration) GetPolicies(papAlias string) ([]hexapolicy.PolicyInfo, error) {
	i.checkOpen()
	app, err := i.GetApplicationInfo(papAlias)
	if err != nil {
		return nil, err
	}
	return i.provider.GetPolicyInfo(*i.Opts.Info, *app)
}

/*
SetPolicyInfo applies the specified set of policies to the integrations 'pap'. Depending on the underlying provider,
set replaces all policies or does a reconciliation and performs the necessary changes to make the 'pap' have the same set of policies.
Note: SetPolicyInfo does not support the setting of an individual policy.
*/
func (i *Integration) SetPolicyInfo(papAlias string, policies []hexapolicy.PolicyInfo) (int, error) {
	i.checkOpen()
	app, err := i.GetApplicationInfo(papAlias)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return i.provider.SetPolicyInfo(*i.Opts.Info, *app, policies)
}

/*
ReconcilePolicy returns the set of differences between the supplied policies and the policies reported by the specified 'pap'.
Setting 'diffsOnly' to false will return results that include matched and unsupported policies (e.g. templates). If the
provider implementation does not support reconcile, an error is returned.
*/
func (i *Integration) ReconcilePolicy(papAlias string, policies []hexapolicy.PolicyInfo, diffsOnly bool) ([]hexapolicy.PolicyDif, error) {
	i.checkOpen()
	app, err := i.GetApplicationInfo(papAlias)
	if err != nil {
		return []hexapolicy.PolicyDif{}, err
	}
	switch rp := i.provider.(type) {
	case PolicyProvider.V2Provider:
		return rp.Reconcile(*i.Opts.Info, *app, policies, diffsOnly)
	default:
		return []hexapolicy.PolicyDif{}, errors.New("provider does not support reconcile")
	}
}
