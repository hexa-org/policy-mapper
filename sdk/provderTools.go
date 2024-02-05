package sdk

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/providers/aws/avpProvider"
	"github.com/hexa-org/policy-mapper/providers/googlecloud/iapProvider"
	"github.com/hexa-org/policy-mapper/providers/test"
	"github.com/hexa-org/policy-mapper/providers/v2providerwrapper"
)

const (
	ProviderTypeAvp     string = avpProvider.ProviderTypeAvp
	ProviderTypeGcp     string = "google_cloud"
	ProviderTypeMock    string = test.ProviderTypeMock
	ProviderTypeCognito string = v2providerwrapper.ProviderTypeCognito
	ProviderTypeAzure   string = v2providerwrapper.ProviderTypeAzure
	EnvTestProvider     string = "HEXA_TEST_PROVIDER" // EnvTestProvider overrides whatever provider is requested and uses the specified provider instead (by name)
)

type Integration struct {
	Alias    string                                    `json:"alias"`
	Opts     Options                                   `json:"options"`
	Apps     map[string]policyprovider.ApplicationInfo `json:"apps"`
	provider policyprovider.Provider                   `json:"-"`
}

/*
OpenIntegration accepts a json byte stream and parses into an IntegrationInfo which can be used to invoke the
provider features. An IntegrationInfo struct consists of:

- integrationInfo - PolicyProvider.IntegrationInfo information defining the provider type and the credential used to access. If not provided, it must be provided using Options

- options - one or more configuration functions for configuring provider See: sdk.Options
*/
func OpenIntegration(integrationInfo *policyprovider.IntegrationInfo, options ...func(*Options)) (*Integration, error) {

	i := &Integration{
		Opts: Options{},
	}

	if integrationInfo != nil {
		i.Opts.Info = integrationInfo
	}
	for _, opt := range options {
		opt(&i.Opts)
	}

	err := i.open()

	return i, err
}

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
	switch provType {
	case ProviderTypeAvp:

		i.provider = avpProvider.NewAvpProvider(i.Opts)

		return nil

	case ProviderTypeGcp:
		i.provider = iapProvider.NewGoogleProvider(i.Opts)

		return nil

	case ProviderTypeAzure, ProviderTypeCognito:
		var err error
		i.provider, err = v2providerwrapper.NewV2ProviderWrapper(provType, *i.Opts.Info)
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

// GetType returns the type of underlying provider. See: sdk.PROVIDER_TYPE_ values. If not defined, "ERROR" is returned.
func (i *Integration) GetType() string {
	if i.Opts.Info == nil {
		return "ERROR"
	}
	return i.Opts.Info.Name
}

func (i *Integration) checkOpen() {
	if i.provider == nil {
		_ = i.open()
	}
}

func (i *Integration) GetProvider() policyprovider.Provider {
	return i.provider
}

/*
GetPolicyApplicationPoints invokes Provider.DiscoverApplications method to locate applications or policy application
points available within a platform Integration. The 'aliasGen' func parameter is used to generate a local alias for the
application. If 'nil' is passed, the ObjectId value from ApplicationInfo is used as the alias.
*/
func (i *Integration) GetPolicyApplicationPoints(aliasGen func() string) ([]policyprovider.ApplicationInfo, error) {
	i.checkOpen()

	aliasMap := map[string]string{}
	if i.Apps != nil {
		for k, app := range i.Apps {
			aliasMap[app.ObjectID] = k
		}
	}

	var apps []policyprovider.ApplicationInfo
	var err error

	apps, err = i.provider.DiscoverApplications(*i.Opts.Info)
	if err != nil {
		return nil, err
	}

	newAppMap := make(map[string]policyprovider.ApplicationInfo, len(apps))
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

func (i *Integration) GetApplicationInfo(papAlias string) (*policyprovider.ApplicationInfo, error) {
	if i.Apps == nil {
		_, err := i.GetPolicyApplicationPoints(nil)
		if err != nil {
			return nil, err
		}
	}
	info, exist := i.Apps[papAlias]

	if exist {
		return &info, nil
	}

	// Check for match by object id
	for _, app := range i.Apps {
		if app.ObjectID == papAlias {
			return &app, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("alias [%s] not found", papAlias))
}

/*
GetPolicies queries the designated 'pap' and returns a set of mapped hexapolicy.PolicyInfo policies.
*/
func (i *Integration) GetPolicies(papAlias string) (*hexapolicy.Policies, error) {
	i.checkOpen()
	var err error
	app, err := i.GetApplicationInfo(papAlias)
	if err != nil {
		return nil, err
	}

	var pols []hexapolicy.PolicyInfo

	pols, err = i.provider.GetPolicyInfo(*i.Opts.Info, *app)
	if err != nil {
		return nil, err
	}
	return &hexapolicy.Policies{
		Policies: pols,
		App:      &app.ObjectID,
	}, nil

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
func (i *Integration) ReconcilePolicy(papAlias string, comparePolicies []hexapolicy.PolicyInfo, diffsOnly bool) ([]hexapolicy.PolicyDif, error) {
	i.checkOpen()
	app, err := i.GetApplicationInfo(papAlias)
	if err != nil {
		return []hexapolicy.PolicyDif{}, err
	}
	switch rp := i.provider.(type) {
	case policyprovider.V2Provider:

		return rp.Reconcile(*i.Opts.Info, *app, comparePolicies, diffsOnly)
	default:
		existPolicies, err := i.GetPolicies(papAlias)
		if err != nil {
			return []hexapolicy.PolicyDif{}, err
		}
		return existPolicies.ReconcilePolicies(comparePolicies, diffsOnly), nil
	}
}
