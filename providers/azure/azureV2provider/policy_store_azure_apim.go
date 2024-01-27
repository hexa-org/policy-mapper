package azureV2provider

import (
	"github.com/hexa-org/policy-mapper/models/rbac/policystore"
	apimnvstore "github.com/hexa-org/policy-mapper/providers/azure/azapim/policystore"
	logger "golang.org/x/exp/slog"
)

type apimPolicyProvider struct {
	key           []byte
	resourceGroup string
	serviceName   string
}

func (a *apimPolicyProvider) Provider() (policystore.PolicyBackendSvc[any], error) {
	policyStore, err := apimnvstore.NewNamedValuePolicyStoreSvc(a.key, nil, a.resourceGroup, a.serviceName)
	if err != nil {
		logger.Error("apimPolicyProvider.Provider",
			"msg", "failed to create NamedValuePolicyStoreSvc",
			"error", err)
		return nil, err
	}
	return policyStore, nil
}

func NewApimPolicyProvider(key []byte, resourceGroup string, serviceName string) PolicyStore[any] {
	return &apimPolicyProvider{key: key, resourceGroup: resourceGroup, serviceName: serviceName}
}
