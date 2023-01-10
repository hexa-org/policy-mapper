package policysupport

import "policy-conditions/policySupport/conditions"

const (
	SAnyUser   string = "any"
	SAnyAuth   string = "anyAuthenticated"
	SBasicAuth string = "basic"
	SJwtAuth   string = "jwt"
	SSamlAuth  string = "saml"
	SCidr      string = "net"
)

type Policies struct {
	Policies []PolicyInfo `json:"policies"`
}

type PolicyInfo struct {
	Meta      MetaInfo                  `validate:"required"`
	Actions   []ActionInfo              `validate:"required"`
	Subject   SubjectInfo               `validate:"required"`
	Object    ObjectInfo                `validate:"required"`
	Condition *conditions.ConditionInfo `json:",omitempty"` // Condition is optional
}

type MetaInfo struct {
	Version string `validate:"required"`
}

type ActionInfo struct {
	ActionUri string `validate:"required"`
}

type SubjectInfo struct {
	Members []string `validate:"required"`
}

type ObjectInfo struct {
	ResourceID string `json:"resource_id" validate:"required"`
}
