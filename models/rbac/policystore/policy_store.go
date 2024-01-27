package policystore

import (
	"github.com/hexa-org/policy-mapper/api/idp"
	"github.com/hexa-org/policy-mapper/models/rbac/rar"
)

type PolicyBackendSvc[R any] interface {
	GetPolicies(info idp.AppInfo) ([]rar.ResourceActionRoles, error)
	SetPolicy(rar rar.ResourceActionRoles) error
}
