package v2providerwrapper

import (
	"errors"

	"github.com/hexa-org/policy-mapper/api/idp"
	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/models/rbac/policystore"
	"github.com/hexa-org/policy-mapper/models/rbac/rar"
	"github.com/hexa-org/policy-mapper/models/rbac/rarprovider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/providers/aws/cognitoProvider"
	"github.com/hexa-org/policy-mapper/providers/azure/azureV2provider"
)

type ProviderWrapper struct {
	name           string
	appInfoService idp.AppInfoSvc
	service        rarprovider.ProviderService
}

const (
	ProviderTypeCognito string = "cognito"
	ProviderTypeAzure   string = "azure"
)

func (p ProviderWrapper) Name() string {
	return p.name
}

func (p ProviderWrapper) DiscoverApplications(_ policyprovider.IntegrationInfo) ([]policyprovider.ApplicationInfo, error) {
	idpApps, err := p.appInfoService.GetApplications()
	if err != nil {
		return nil, err
	}
	var apps []policyprovider.ApplicationInfo
	for _, idpApp := range idpApps {
		app := policyprovider.ApplicationInfo{
			ObjectID:    idpApp.Id(),
			Name:        idpApp.Name(),
			Description: idpApp.DisplayName(),
			Service:     idpApp.Type(),
		}
		apps = append(apps, app)
	}
	return apps, nil
}

func (p ProviderWrapper) GetPolicyInfo(_ policyprovider.IntegrationInfo, appInfo policyprovider.ApplicationInfo) ([]hexapolicy.PolicyInfo, error) {
	idpApp, err := p.appInfoService.GetApplication(appInfo.ObjectID)
	if err != nil {
		return nil, err
	}
	pInfos, err := p.service.GetPolicyInfo(idpApp)
	return pInfos, err
}

func (p ProviderWrapper) SetPolicyInfo(_ policyprovider.IntegrationInfo, appInfo policyprovider.ApplicationInfo, infos []hexapolicy.PolicyInfo) (status int, foundErr error) {
	idpApp, err := p.appInfoService.GetApplication(appInfo.ObjectID)
	if err != nil {
		return 400, err
	}

	err = p.service.SetPolicyInfo(idpApp, infos)
	if err != nil {
		return 400, err
	}
	return 200, nil
}

func NewV2ProviderWrapper(name string, info policyprovider.IntegrationInfo) (policyprovider.Provider, error) {
	switch name {
	case ProviderTypeCognito:
		resAttrDef := cognitoProvider.NewAttributeDefinition("Resource", "string", true, false)
		actionsAttrDef := cognitoProvider.NewAttributeDefinition("Action", "string", false, true)
		membersDef := cognitoProvider.NewAttributeDefinition("Members", "string", false, false)
		tableDef := cognitoProvider.NewTableDefinition(resAttrDef, actionsAttrDef, membersDef)
		policyStore := cognitoProvider.NewDynamicItemStore(cognitoProvider.AwsPolicyStoreTableName, info.Key, tableDef)
		idp := cognitoProvider.NewCognitoIdp(info.Key)

		appInfoSvc, err := idp.Provider()
		if err != nil {
			return nil, err
		}

		var backendService policystore.PolicyBackendSvc[rar.DynamicResourceActionRolesMapper]
		backendService, err = policyStore.Provider()
		if err != nil {
			return nil, err
		}

		return &ProviderWrapper{
			name:           name,
			appInfoService: appInfoSvc,
			service:        rarprovider.NewProviderService[rar.DynamicResourceActionRolesMapper](appInfoSvc, backendService),
		}, nil
	case ProviderTypeAzure:
		idp := azureV2provider.NewApimAppProvider(info.Key)
		appInfoSvc, err := idp.Provider()
		if err != nil {
			return nil, err
		}
		policyStoreSvc, err := azureV2provider.NewEmptyPolicyStore().Provider()
		if err != nil {
			return nil, err
		}

		service := rarprovider.NewProviderService[rar.DynamicResourceActionRolesMapper](appInfoSvc, policyStoreSvc)
		return &ProviderWrapper{
			name:           name,
			appInfoService: appInfoSvc,
			service:        service,
		}, nil
	default:
	}

	return nil, errors.New("Unsupported type: " + name)
}
