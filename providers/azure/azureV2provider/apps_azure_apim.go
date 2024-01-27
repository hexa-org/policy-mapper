package azureV2provider

import (
	"github.com/hexa-org/policy-mapper/api/idp"
	"github.com/hexa-org/policy-mapper/providers/azure/azapim/apps"
)

type apimAppProvider struct {
	key []byte
}

func (a *apimAppProvider) Provider() (idp.AppInfoSvc, error) {
	return apps.NewAppInfoSvc(a.key, nil)
}

func NewApimAppProvider(key []byte) Idp {
	return &apimAppProvider{key: key}
}
