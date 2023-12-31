package hexapolicy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
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

	IdqlVersion string = "0.6"
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

func (p *PolicyInfo) String() string {
	policyBytes, _ := json.MarshalIndent(p, "", " ")
	return string(policyBytes)
}

/*
CalculateEtag calculates an ETAG hash value for the policy which includes the Subject, Actions, Object, and Conditions objects only
*/
func (p *PolicyInfo) CalculateEtag() string {
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

	p.Meta.Etag = etagValue
	return etagValue
}

// Equals compares the CalculateEtag hash values to determine if the policies are equal. Note: does NOT compare meta information.
func (p *PolicyInfo) Equals(hexaPolicy PolicyInfo) bool {
	// Re-calculate the policy etag and compare in case either has changed.
	return p.CalculateEtag() == hexaPolicy.CalculateEtag()
}

const (
	COMPARE_EQUAL         = "EQUAL"
	COMPARE_DIF_ACTION    = "ACTION"
	COMPARE_DIF_SUBJECT   = "SUBJECT"
	COMPARE_DIF_OBJECT    = "OBJECT"
	COMPARE_DIF_CONDITION = "CONDITION"
)

func (p *PolicyInfo) Compare(hexaPolicy PolicyInfo) []string {
	// First do a textual compare
	if p.Equals(hexaPolicy) {
		return []string{COMPARE_EQUAL}
	}

	var difs = make([]string, 0)

	// Now do a semantic compare (e.g. things can be different order but the same)
	if !p.Subject.equals(&hexaPolicy.Subject) {
		difs = append(difs, COMPARE_DIF_SUBJECT)
	}

	if !p.actionEquals(hexaPolicy.Actions) {
		difs = append(difs, COMPARE_DIF_ACTION)
	}

	if !p.Object.equals(&hexaPolicy.Object) {
		difs = append(difs, COMPARE_DIF_OBJECT)
	}

	if p.Condition != nil && hexaPolicy.Condition == nil || p.Condition == nil && p.Condition != nil {
		difs = append(difs, COMPARE_DIF_CONDITION)
	} else {
		if p.Condition != nil && !p.Condition.Equals(hexaPolicy.Condition) {
			difs = append(difs, COMPARE_DIF_CONDITION)
		}
	}

	if len(difs) == 0 {
		return []string{COMPARE_EQUAL}
	}

	return difs
}

func (p *PolicyInfo) actionEquals(actions []ActionInfo) bool {
	if len(p.Actions) != len(actions) {
		return false
	}
	for _, action := range p.Actions {
		isMatch := false
		for _, caction := range actions {
			if strings.EqualFold(action.ActionUri, caction.ActionUri) {
				isMatch = true
				break
			}
		}
		if !isMatch {
			return false
		}
	}
	return true
}

type MetaInfo struct {
	Version      string                 `json:"Version,omitempty" validate:"required"` // this is the idql policy format version
	SourceData   map[string]interface{} `json:",omitempty"`                            // Logistical information required to map in source provider, e.g. type, identifiers
	Description  string                 `json:",omitempty"`
	Created      *time.Time             `json:",omitempty"`
	Modified     *time.Time             `json:",omitempty"`
	Etag         string                 `json:",omitempty"`
	PolicyId     *string                `json:",omitempty"`
	PapId        *string                `json:",omitempty"`
	ProviderType string                 `json:",omitempty"`
}

type ActionInfo struct {
	ActionUri string `validate:"required"`
}

type SubjectInfo struct {
	Members []string `validate:"required"`
}

func (s *SubjectInfo) equals(subject *SubjectInfo) bool {
	if len(s.Members) != len(subject.Members) {
		return false
	}
	for _, member := range s.Members {
		isMatch := false
		for _, cmember := range subject.Members {
			if strings.EqualFold(member, cmember) {
				isMatch = true
				break
			}
		}
		if !isMatch {
			return false
		}
	}
	return true
}

type ObjectInfo struct {
	ResourceID string `json:"resource_id" validate:"required"`
}

func (o *ObjectInfo) equals(object *ObjectInfo) bool {
	return o.ResourceID == object.ResourceID
}

var (
	TYPE_NEW     = "NEW"
	TYPE_EQUAL   = "MATCHED"
	TYPE_UPDATE  = "UPDATE"
	TYPE_DELETE  = "DELETE"
	TYPE_IGNORED = "UNSUPPORTED"
)

type PolicyDif struct {
	Type          string
	DifTypes      []string
	PolicyExist   *[]PolicyInfo // for n to 1
	PolicyCompare *PolicyInfo
}

func (d *PolicyDif) Report() string {
	switch d.Type {
	case TYPE_NEW, TYPE_EQUAL, TYPE_IGNORED:
		return fmt.Sprintf("DIF: %s\n%s", d.Type, d.PolicyCompare.String())
	case TYPE_DELETE:
		policies := *d.PolicyExist
		sourceMeta := policies[0].Meta.SourceData
		metaBytes, _ := json.Marshal(sourceMeta)
		return fmt.Sprintf("DIF: %s PolicyId: %s", d.Type, string(metaBytes))
	case TYPE_UPDATE:
		return fmt.Sprintf("DIF: %s %v\n%s", d.Type, d.DifTypes, d.PolicyCompare.String())
	default:
		return fmt.Sprintf("DIF: %s\n%s", "Unexpected type", d.PolicyCompare.String())
	}
}

func ReconcilePolicies(existingPolicies []PolicyInfo, comparePolicies []PolicyInfo, diffsOnly bool) ([]PolicyDif, error) {
	var res = make([]PolicyDif, 0)

	var policyIdMap = make(map[string]PolicyInfo, len(existingPolicies))
	for _, policy := range existingPolicies {
		policyId := *policy.Meta.PolicyId
		policyIdMap[policyId] = policy
	}
	for _, comparePolicy := range comparePolicies {

		meta := comparePolicy.Meta

		policyId := *meta.PolicyId
		sourcePolicy, exists := policyIdMap[policyId]

		if exists {
			differenceTypes := comparePolicy.Compare(sourcePolicy)
			if slices.Contains(differenceTypes, COMPARE_EQUAL) {
				if !diffsOnly {
					// policy matches
					dif := PolicyDif{
						Type:          TYPE_EQUAL,
						DifTypes:      nil,
						PolicyExist:   &[]PolicyInfo{sourcePolicy},
						PolicyCompare: &comparePolicy,
					}
					res = append(res, dif)
				}
				delete(policyIdMap, policyId) // Remove to indicate existing policy handled
				continue                      // nothing to do
			}
			// This is a modify request
			newPolicy := comparePolicy
			dif := PolicyDif{
				Type:          TYPE_UPDATE,
				DifTypes:      differenceTypes,
				PolicyExist:   &[]PolicyInfo{sourcePolicy},
				PolicyCompare: &newPolicy,
			}
			res = append(res, dif)
			delete(policyIdMap, policyId) // Remove to indicate existing policy handled
			continue
		}

		// At this point no match was found. So assume new

		newPolicy := comparePolicy
		dif := PolicyDif{
			Type:          TYPE_NEW,
			DifTypes:      nil,
			PolicyExist:   nil,
			PolicyCompare: &newPolicy,
		}
		res = append(res, dif)

	}

	// For each remaining pre-existing policy there is an implied delete
	if len(policyIdMap) > 0 {
		fmt.Printf("%v existing AVP policies will be removed.\n", len(policyIdMap))
		for _, policy := range policyIdMap {
			dif := PolicyDif{
				Type:          TYPE_DELETE,
				DifTypes:      nil,
				PolicyExist:   &[]PolicyInfo{policy},
				PolicyCompare: nil,
			}
			res = append(res, dif)
		}
	}
	return res, nil
}
