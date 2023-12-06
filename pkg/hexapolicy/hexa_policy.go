package hexapolicy

import (
    "time"

    "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
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

type MetaInfo struct {
    Version     string      `validate:"required"`
    SourceMeta  interface{} `json:",omitempty"` // Logistical information required to map in source provider, e.g. type, identifiers
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
