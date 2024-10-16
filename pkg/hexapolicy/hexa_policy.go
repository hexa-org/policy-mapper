package hexapolicy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/parser"
	"github.com/hhsnopek/etag"
	log "golang.org/x/exp/slog"
)

const (
	SubjectAnyUser   string = "any"
	SubjectAnyAuth   string = "anyAuthenticated"
	SubjectBasicAuth string = "basic"
	SubjectJwtAuth   string = "jwt"
	SubjectSamlAuth  string = "saml"
	// SCidr      string = "net"

	IdqlVersion string = "0.7"
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

// PolicyInfo holds a single IDQL Policy Statement
type PolicyInfo struct {
	Meta      MetaInfo                  `json:"meta" validate:"required"`             // Meta holds additional information about the policy including policy management data
	Subjects  SubjectInfo               `json:"subjects,subject" validate:"required"` // Subjects holds the subject clause of an IDQL policy
	Actions   []ActionInfo              `json:"actions" validate:"required"`          // Actions holds one or moe action uris
	Object    ObjectInfo                `json:"object" validate:"required"`           // Object the resource, application, or system to which a policy applies
	Condition *conditions.ConditionInfo `json:"condition,omitempty"`                  // Condition is optional // Condition is an IDQL filter condition (e.g. ABAC rule) which must also be met
	Scope     *ScopeInfo                `json:"scope,omitempty"`                      // Scope represents obligations returned to a PEP (e.g. attributes, where clause)
}

func (p *PolicyInfo) String() string {
	policyBytes, _ := json.MarshalIndent(p, "", " ")
	return string(policyBytes)
}

// problemPart returns a string value around the detected offset
func problemPart(data []byte, offset int) string {
	start := offset - 10
	end := offset + 10
	if start < 0 {
		start = 0
	}
	if end > len(data) {
		end = len(data)
	}
	return string(data[start:end])
}

// EnhanceError adds improved details by adding information from parsed json that was invalid
func EnhanceError(err error, data []byte) error {
	switch jsonErr := err.(type) {
	case *json.SyntaxError:
		return fmt.Errorf("%s - error near '%s'", err, problemPart(data, int(jsonErr.Offset)))
	case *json.UnmarshalTypeError:
		return fmt.Errorf("%s - type error near '%s'", err, problemPart(data, int(jsonErr.Offset)))
	}

	return err
}

func (p *PolicyInfo) UnmarshalJSON(data []byte) error {
	if data == nil || len(data) == 0 {
		return nil
	}
	var fieldMap map[string]*json.RawMessage
	if err := json.Unmarshal(data, &fieldMap); err != nil {
		return err
	}
	var meta MetaInfo
	var subjects SubjectInfo
	var actions []ActionInfo
	var object ObjectInfo
	var scope *ScopeInfo
	var condition *conditions.ConditionInfo

	for k, v := range fieldMap {
		var err error
		switch k {
		case "Meta", "meta":
			err = json.Unmarshal(*v, &meta)
			if !strings.EqualFold(meta.Version, IdqlVersion) {
				log.Warn("Auto-upgrading policy to "+IdqlVersion, "PolicyId", meta.PolicyId)
				meta.Version = IdqlVersion
			}
		case "Subjects", "subjects":

			err = json.Unmarshal(*v, &subjects)
		case "Subject", "subject":
			var oldSub OldSubjectInfo
			err = json.Unmarshal(*v, &oldSub)
			if err == nil {
				subjects = oldSub.Members
			}
		case "Actions", "actions":
			if v == nil {
				continue // if null passed to "actions"
			}
			err = json.Unmarshal(*v, &actions)
			if err != nil {
				// try old action format
				var oldAction []OldActionInfo
				err = json.Unmarshal(*v, &oldAction)
				if err == nil {
					var items []ActionInfo
					for _, v := range oldAction {
						items = append(items, ActionInfo(v.ActionUri))
					}
					actions = items
				}
			}
		case "Object", "object":
			err = json.Unmarshal(*v, &object)
			if err != nil {
				// try old object
				var oldObject OldObjectInfo
				err = json.Unmarshal(*v, &oldObject)
				if err == nil {
					object = ObjectInfo(oldObject.ResourceID)
				}
			}
		case "Scope", "scope":
			err = json.Unmarshal(*v, &scope)
		case "Condition", "condition":
			err = json.Unmarshal(*v, &condition)
		}
		if err != nil {
			return EnhanceError(err, *v)
		}
	}

	p.Meta = meta
	p.Subjects = subjects
	p.Actions = actions
	p.Object = object
	p.Scope = scope
	p.Condition = condition
	return nil
}

/*
CalculateEtag calculates an ETAG hash value for the policy which includes the Subjects, Actions, Object, and
Conditions objects only
*/
func (p *PolicyInfo) CalculateEtag() string {
	pderef := *p // this was causing a pointer interaction - so deref
	subjectBytes, _ := json.Marshal(pderef.Subjects)
	actionBytes, _ := json.Marshal(pderef.Actions)
	objectBytes, _ := json.Marshal(pderef.Object)
	conditionBytes := make([]byte, 0)
	if p.Condition != nil {
		conditionBytes, _ = json.Marshal(p.Condition)
	}
	scopeBytes := make([]byte, 0)
	if p.Scope != nil {
		scopeBytes, _ = json.Marshal(p.Condition)
	}

	policyBytes := make([]byte, 0)
	policyBytes = append(policyBytes, subjectBytes...)
	policyBytes = append(policyBytes, actionBytes...)
	policyBytes = append(policyBytes, objectBytes...)
	policyBytes = append(policyBytes, conditionBytes...)
	policyBytes = append(policyBytes, scopeBytes...)

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
	if !(p.Subjects.Equals(hexaPolicy.Subjects) && p.ActionsEqual(hexaPolicy.Actions) && p.Object.equals(&hexaPolicy.Object)) {
		return false
	}

	if p.Condition != nil {
		if hexaPolicy.Condition == nil {
			return false
		}
		if !p.Condition.Equals(hexaPolicy.Condition) {
			return false
		}
	}
	if p.Condition == nil && hexaPolicy.Condition != nil {
		return false
	}

	if p.Scope != nil {
		if hexaPolicy.Scope == nil {
			return false
		}
		if !p.Scope.Equals(hexaPolicy.Scope) {
			return false
		}
	}
	if p.Scope == nil && hexaPolicy.Scope != nil {
		return false
	}
	return true
}

const (
	CompareEqual        string = "EQUAL"
	CompareDifAction    string = "ACTION"
	CompareDifSubject   string = "SUBJECT"
	CompareDifObject    string = "OBJECT"
	CompareDifCondition string = "CONDITION"
)

// Compare reports the differences between two policies, one or more of CompareEqual, CompareDifAction,
// CompareDifSubject, CompareDifObject, CompareDifCondition
func (p *PolicyInfo) Compare(hexaPolicy PolicyInfo) []string {
	// First do a textual compare
	if p.Equals(hexaPolicy) {
		return []string{CompareEqual}
	}

	var difs = make([]string, 0)

	// Now do a semantic compare (e.g. things can be different order but the same)
	if !p.Subjects.Equals(hexaPolicy.Subjects) {
		difs = append(difs, CompareDifSubject)
	}

	if !p.ActionsEqual(hexaPolicy.Actions) {
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

func (p *PolicyInfo) ActionsEqual(actions []ActionInfo) bool {
	if actions == nil || len(p.Actions) != len(actions) {
		return false
	}
	for _, action := range p.Actions {
		isMatch := false
		for _, compareAction := range actions {
			if action.Equals(compareAction) {
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
	Version      string                 `json:"version,omitempty" validate:"required"` // Version is the idql policy format version
	SourceData   map[string]interface{} `json:"sourceData,omitempty"`                  // SourceData custom map for providers (e.g. AVP), e.g. type, identifiers
	Description  string                 `json:"description,omitempty"`                 // Description is an information description of the policy
	Created      *time.Time             `json:"created,omitempty"`                     // Created is the time the policy was originally created
	Modified     *time.Time             `json:"modified,omitempty"`                    // Modified inicates the last time the policy was updated or created, used in change detection in some providers
	Etag         string                 `json:"etag,omitempty"`                        // Etag holds a calculated hash value used for change detection See Policy.CalculateEtag()
	PolicyId     *string                `json:"policyId,omitempty"`                    // PolicyId is a unique identifier for a policy, may be assigned by the source provider
	PapId        *string                `json:"papId,omitempty"`                       // PapId is the source Policy Application Point or Application where the policy originated
	ProviderType string                 `json:"providerType,omitempty"`                // ProviderType is the SDK provider type indicating the source of the policy
}

type OldActionInfo struct {
	ActionUri string `json:"actionUri" validate:"required"`
}

type ActionInfo string

func (a ActionInfo) String() string {
	return string(a)
}

func (a ActionInfo) EntityPath() *parser.EntityPath {
	return parser.ParseEntityPath(a.String())
}

func (a ActionInfo) Equals(action ActionInfo) bool {
	return strings.EqualFold(string(a), string(action))
}

type OldSubjectInfo struct {
	Members []string `json:"members" validate:"required"`
}

type SubjectInfo []string

func (s SubjectInfo) String() []string {
	return s
}

func (s SubjectInfo) Equals(subjects SubjectInfo) bool {
	if len(s) != len(subjects) {
		return false
	}
	for _, member := range s {
		isMatch := false
		for _, compareMember := range subjects {
			if strings.EqualFold(member, compareMember) {
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

func (s SubjectInfo) EntityPaths() *[]parser.EntityPath {
	ret := make([]parser.EntityPath, len(s))
	for i, subject := range s {
		path := parser.ParseEntityPath(subject)
		if path != nil {
			ret[i] = *path
		}
	}
	return &ret
}

type OldObjectInfo struct {
	ResourceID string `json:"resource_id" validate:"required"`
}

type ObjectInfo string

func (o *ObjectInfo) String() string {
	return string(*o)
}

func (o *ObjectInfo) EntityPath() *parser.EntityPath {
	return parser.ParseEntityPath(o.String())
}

func (o *ObjectInfo) equals(object *ObjectInfo) bool {
	if object == nil {
		return false
	}
	return strings.EqualFold(o.String(), object.String())
}

// ScopeInfo represents obligations passed to a PEP. For example a `Filter` is used to constrain the rows of a database.
// `Attributes` lists the columns or attributes that may be returned. Scopes are NOT used in determining which policy
// is applied.
type ScopeInfo struct {
	Filter     *string  `json:"filter,omitempty"`     // Filter urn like value that starts with either sql: or idql: to indicate the filter is either a SQL statement or an IDQL Filter/Condition expression
	Attributes []string `json:"attributes,omitempty"` // Attributes is a list of columns or attributes that may be returned by the PEP
}

const (
	ScopeTypeSQL        string = "sql"
	ScopeTypeIDQL       string = "idql"
	ScopeTypeUnassigned string = "na"
)

// Equals returns equality based on string compare. This does not lexically compare filters.
// This function is intended to determine if a policy element has changed.
func (s *ScopeInfo) Equals(scope *ScopeInfo) bool {
	if s.Type() != scope.Type() {
		return false
	}
	if s.Filter != nil {
		s1 := *s.Filter
		s2 := *scope.Filter
		if !(s1 == s2) {
			return false
		}
	}

	if len(s.Attributes) != len(scope.Attributes) {
		return false
	}
	for _, attr := range s.Attributes {
		isMatch := false
		for _, cAttr := range scope.Attributes {
			if strings.EqualFold(attr, cAttr) {
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

func (s *ScopeInfo) Type() string {
	if s.Filter == nil || *s.Filter == "" {
		return ScopeTypeUnassigned
	}
	parts := strings.Split(*s.Filter, ":")
	switch strings.ToLower(parts[0]) {
	case ScopeTypeSQL:
		return ScopeTypeSQL
	case ScopeTypeIDQL:
		return ScopeTypeIDQL
	}
	return ScopeTypeUnassigned
}

// Value returns the raw value without the prefix
func (s *ScopeInfo) Value() string {
	switch s.Type() {
	case ScopeTypeSQL:
		value := *s.Filter
		return value[4:]
	case ScopeTypeIDQL:
		value := *s.Filter
		return value[5:]
	}
	return *s.Filter
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
	PolicyExist   []PolicyInfo // for n to 1
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
		sourcePolicy = PolicyInfo{}
		var policyId string
		if meta.PolicyId != nil {
			policyId = *meta.PolicyId
			sourcePolicy, exists = policyIdMap[policyId]
		}
		pExisting := []PolicyInfo{sourcePolicy}
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
						PolicyExist:   pExisting,
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
				PolicyExist:   pExisting,
				PolicyCompare: &newPolicy,
			}
			res = append(res, dif)
			delete(policyIdMap, policyId) // Remove to indicate existing policy handled
			continue
		}

		// Check for a match based on hash
		sourcePolicy, hashExists := policyEtagMap[comparePolicy.CalculateEtag()]
		pExisting = []PolicyInfo{sourcePolicy}
		if hashExists {
			if !diffsOnly {
				// Because it is a hash compare, the policies must be equal (even though metadata may be different)
				// policy matches
				dif := PolicyDif{
					Type:          ChangeTypeEqual,
					Hash:          sourcePolicy.Meta.Etag,
					DifTypes:      []string{CompareEqual},
					PolicyExist:   pExisting,
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
				PolicyExist:   []PolicyInfo{policy},
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
				PolicyExist:   []PolicyInfo{pol},
				PolicyCompare: nil,
			}
			res = append(res, dif)
		}
	}
	return res
}
