package cognitoProvider

import (
	"github.com/hexa-org/policy-mapper/api/idp"
	"github.com/hexa-org/policy-mapper/mapper/rbac/apps"
	"github.com/hexa-org/policy-mapper/providers/aws/cognitoidp"
)

type cognitoIdp struct {
	name string
	key  []byte
}

func NewCognitoIdp(key []byte) apps.Idp {
	return &cognitoIdp{key: key}
}

func (c *cognitoIdp) Provider() (idp.AppInfoSvc, error) {
	return cognitoidp.NewAppInfoSvc(c.key)
}
