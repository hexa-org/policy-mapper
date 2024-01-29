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
	App      *string      `json:"app,omitempty"`
}

func (p *Policies) CalculateEtags() {
	if p.Policies == nil {
		return
	}
	for i := range p.Policies {
		p.Policies[i].CalculateEtag()
	}
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
	pderef := *p // this was causing a pointer interaction - so deref
	subjectBytes, _ := json.Marshal(pderef.Subject)
	actionBytes, _ := json.Marshal(pderef.Actions)
	objectBytes, _ := json.Marshal(pderef.Object)
	conditionBytes := make([]byte, 0)
	if p.Condition != nil {
		conditionBytes, _ = json.Marshal(p.Condition)
	}

	policyBytes := make([]byte, 0)
	policyBytes = append(policyBytes, subjectBytes...)
	policyBytes = append(policyBytes, actionBytes...)
	policyBytes = append(policyBytes, objectBytes...)
	policyBytes = append(policyBytes, conditionBytes...)

	etagValue := etag.Generate(policyBytes, false)
	if etagValue[0:1] == "\"" {
		etagValue = etagValue[1:(len(etagValue) - 1)]
	}
	p.Meta.Etag = etagValue
	return etagValue
}

// Equals compares values to determine if the policies are equal. Note: does NOT compare meta information.
func (p *PolicyInfo) Equals(hexaPolicy PolicyInfo) bool {
	// Re-calculate the policy etag and compare in case either has changed.
	if p.CalculateEtag() == hexaPolicy.CalculateEtag() {
		return true
	}

	// check for semantic equivalence.
	return p.Subject.equals(&hexaPolicy.Subject) && p.actionEquals(hexaPolicy.Actions) && p.Object.equals(&hexaPolicy.Object)

}

const (
	CompareEqual        string = "EQUAL"
	CompareDifAction    string = "ACTION"
	CompareDifSubject   string = "SUBJECT"
	CompareDifObject    string = "OBJECT"
	CompareDifCondition string = "CONDITION"
)

func (p *PolicyInfo) Compare(hexaPolicy PolicyInfo) []string {
	// First do a textual compare
	if p.Equals(hexaPolicy) {
		return []string{CompareEqual}
	}

	var difs = make([]string, 0)

	// Now do a semantic compare (e.g. things can be different order but the same)
	if !p.Subject.equals(&hexaPolicy.Subject) {
		difs = append(difs, CompareDifSubject)
	}

	if !p.actionEquals(hexaPolicy.Actions) {
		difs = append(difs, CompareDifAction)
	}

	if !p.Object.equals(&hexaPolicy.Object) {
		difs = append(difs, CompareDifObject)
	}

	if p.Condition != nil && hexaPolicy.Condition == nil || p.Condition == nil && p.Condition != nil {
		difs = append(difs, CompareDifCondition)
	} else {
		if p.Condition != nil && !p.Condition.Equals(hexaPolicy.Condition) {
			difs = append(difs, CompareDifCondition)
		}
	}

	if len(difs) == 0 {
		return []string{CompareEqual}
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
	ChangeTypeNew    = "NEW"
	ChangeTypeEqual  = "MATCHED"
	ChangeTypeUpdate = "UPDATE"
	ChangeTypeDelete = "DELETE"
	ChangeTypeIgnore = "UNSUPPORTED"
)

type PolicyDif struct {
	Type          string
	PolicyId      string
	Hash          string
	DifTypes      []string
	PolicyExist   *[]PolicyInfo // for n to 1
	PolicyCompare *PolicyInfo
}

func (d *PolicyDif) getIdentifier() string {
	if d.PolicyId != "" {
		return "PolicyId: " + d.PolicyId
	}
	if d.Hash != "" {
		return "Hash: " + d.Hash
	}
	return ""
}

func (d *PolicyDif) Report() string {
	switch d.Type {
	case ChangeTypeNew, ChangeTypeEqual, ChangeTypeIgnore:
		return fmt.Sprintf("DIF: %s %s\n%s", d.Type, d.getIdentifier(), d.PolicyCompare.String())
	case ChangeTypeDelete:
		return fmt.Sprintf("DIF: %s %s", d.Type, d.getIdentifier())
	case ChangeTypeUpdate:
		return fmt.Sprintf("DIF: %s %s %v\n%s", d.Type, d.getIdentifier(), d.DifTypes, d.PolicyCompare.String())
	default:
		return fmt.Sprintf("DIF: %s %s\n%s", "Unexpected type", d.getIdentifier(), d.PolicyCompare.String())
	}
}

func (p *Policies) ReconcilePolicies(comparePolicies []PolicyInfo, diffsOnly bool) []PolicyDif {
	var res = make([]PolicyDif, 0)
	existingPolicies := p.Policies
	var policyIdMap = make(map[string]PolicyInfo, len(existingPolicies))
	var policyEtagMap = make(map[string]PolicyInfo, len(existingPolicies))

	for _, policy := range existingPolicies {
		if policy.Meta.PolicyId != nil {
			id := *policy.Meta.PolicyId
			policyIdMap[id] = policy
		} else {
			policyEtagMap[policy.CalculateEtag()] = policy
		}
	}

	for _, comparePolicy := range comparePolicies {

		meta := comparePolicy.Meta

		// Because comparePolicy is an iterator, take a copy to avoid it changing
		newPolicy := comparePolicy

		exists := false
		var sourcePolicy PolicyInfo
		var policyId string
		if meta.PolicyId != nil {
			policyId = *meta.PolicyId
			sourcePolicy, exists = policyIdMap[policyId]
		}

		// A policy was matched based on policyId
		if exists {
			differenceTypes := comparePolicy.Compare(sourcePolicy)
			if slices.Contains(differenceTypes, CompareEqual) {
				if !diffsOnly {
					// policy matches, only return an equal difference if diffsOnly is false
					dif := PolicyDif{
						Type:          ChangeTypeEqual,
						PolicyId:      *sourcePolicy.Meta.PolicyId,
						DifTypes:      differenceTypes,
						PolicyExist:   &[]PolicyInfo{sourcePolicy},
						PolicyCompare: &newPolicy,
					}
					res = append(res, dif)
				}
				delete(policyIdMap, policyId) // Remove to indicate existing policy handled
				continue                      // nothing to do
			}

			// This is a modify request
			dif := PolicyDif{
				Type:          ChangeTypeUpdate,
				PolicyId:      *sourcePolicy.Meta.PolicyId,
				DifTypes:      differenceTypes,
				PolicyExist:   &[]PolicyInfo{sourcePolicy},
				PolicyCompare: &newPolicy,
			}
			res = append(res, dif)
			delete(policyIdMap, policyId) // Remove to indicate existing policy handled
			continue
		}

		// Check for a match based on hash
		sourcePolicy, hashExists := policyEtagMap[comparePolicy.CalculateEtag()]
		if hashExists {
			if !diffsOnly {
				// Because it is a hash compare, the policies must be equal (even though meta data may be different)
				// policy matches
				dif := PolicyDif{
					Type:          ChangeTypeEqual,
					Hash:          sourcePolicy.Meta.Etag,
					DifTypes:      []string{CompareEqual},
					PolicyExist:   &[]PolicyInfo{sourcePolicy},
					PolicyCompare: &newPolicy,
				}
				res = append(res, dif)
			}
			delete(policyEtagMap, comparePolicy.Meta.Etag)
			continue
		}

		// At this point no match was found. So assume new
		dif := PolicyDif{
			Type:          ChangeTypeNew,
			PolicyId:      policyId,
			Hash:          comparePolicy.Meta.Etag,
			DifTypes:      nil,
			PolicyExist:   nil,
			PolicyCompare: &newPolicy,
		}
		res = append(res, dif)

	}

	// For each remaining pre-existing policy there is an implied delete
	if len(policyIdMap) > 0 {
		fmt.Printf("%v existing policies with Policy Ids will be removed.\n", len(policyIdMap))
		for _, policy := range policyIdMap {
			dif := PolicyDif{
				Type:          ChangeTypeDelete,
				PolicyId:      *policy.Meta.PolicyId,
				DifTypes:      nil,
				PolicyExist:   &[]PolicyInfo{policy},
				PolicyCompare: nil,
			}
			res = append(res, dif)
		}
	}
	if len(policyEtagMap) > 0 {
		fmt.Printf("%v existing policies (without policy ids) will be removed.\n", len(policyEtagMap))
		for _, policy := range policyEtagMap {
			pol := policy
			dif := PolicyDif{
				Type:          ChangeTypeDelete,
				Hash:          policy.Meta.Etag,
				DifTypes:      nil,
				PolicyExist:   &[]PolicyInfo{pol},
				PolicyCompare: nil,
			}
			res = append(res, dif)
		}
	}
	return res
}
