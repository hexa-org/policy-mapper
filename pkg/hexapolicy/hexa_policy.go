package hexapolicy

import (
	"encoding/json"
	"time"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
	"github.com/hhsnopek/etag"
)

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

func (p *Policies) AddPolicy(info PolicyInfo) {
	p.Policies = append(p.Policies, info)
}

func (p *Policies) AddPolicies(policies Policies) {
	for _, v := range policies.Policies {
		p.AddPolicy(v)
	}
}

type PolicyInfoSaurabh struct {
	Name string
}

type PolicyInfoSaurabhV2 struct {
	Name string
}

type PolicyInfo struct {
	Meta      MetaInfo                  `validate:"required"`
	Subject   SubjectInfo               `validate:"required"`
	Actions   []ActionInfo              `validate:"required"`
	Object    ObjectInfo                `validate:"required"`
	Condition *conditions.ConditionInfo `json:",omitempty"` // Condition is optional
}

/*
Etag calculates an ETAG hash value for the policy which includes the Subject, Actions, Object, and Conditions objects only
*/
func (p *PolicyInfo) Etag() string {
	subjectBytes, _ := json.Marshal(p.Subject)
	actionBytes, _ := json.Marshal(p.Actions)
	objectBytes, _ := json.Marshal(p.Object)
	conditionBytes := make([]byte, 0)
	if p.Condition != nil {
		conditionBytes, _ = json.Marshal(p.Condition)
	}

	policyBytes := make([]byte, 0)
	policyBytes = append(policyBytes, subjectBytes...)
	policyBytes = append(policyBytes, actionBytes...)
	policyBytes = append(policyBytes, objectBytes...)
	policyBytes = append(policyBytes, conditionBytes...)

	etagValue := etag.Generate(policyBytes, true)

	p.Meta.Version = etagValue
	return etagValue
}

// Equals compares the Etag hash values to determine if the policies are equal. Note: does NOT compare meta information.
func (p *PolicyInfo) Equals(hexaPolicy PolicyInfo) bool {
	return p.Etag() == hexaPolicy.Etag()
}

type MetaInfo struct {
	Version     string      `validate:"required"` // this is a json hash representing a hash of the current idql (used for change detection)
	SourceMeta  interface{} `json:",omitempty"`   // Logistical information required to map in source provider, e.g. type, identifiers
	Description string      `json:",omitempty"`
	Created     *time.Time  `json:",omitempty"`
	Modified    *time.Time  `json:",omitempty"`
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
