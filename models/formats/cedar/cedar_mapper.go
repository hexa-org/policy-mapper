package cedar

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
	hexaTypes "github.com/hexa-org/policy-mapper/pkg/hexapolicy/types"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"

	"github.com/hexa-org/policy-mapper/models/conditionLangs/cedarConditions"
	policyjson "github.com/hexa-org/policy-mapper/models/formats/cedar/json"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
)

type CedarMapper struct {
	condMap *cedarConditions.CedarConditionMapper
}

func NewCedarMapper(attrNameMap map[string]string) *CedarMapper {
	return &CedarMapper{condMap: &cedarConditions.CedarConditionMapper{conditions.NewNameMapper(attrNameMap)}}
}

/*
cedar_mapper.go is needed to expose the internal Cedar parser for use by Hexa. In this package we leverage the Cedar Tokenizer
to build up the AST and Policy tree for mapping.
*/

type PolicyPair struct {
	HexaPolicy  *hexapolicy.PolicyInfo
	CedarPolicy *cedar.Policy
	Ast         policyjson.PolicyJSON
	res         strings.Builder
}

type ParseSet struct {
	IdqlPolicies []hexapolicy.PolicyInfo
	Pairs        []PolicyPair

	Pos             int
	loc             string
	conditionMapper *cedarConditions.CedarConditionMapper
}

func (c *CedarMapper) MapCedarPolicyBytes(location string, cedarBytes []byte) (*hexapolicy.Policies, error) {

	policies, err := cedar.NewPolicyListFromBytes(location, cedarBytes)
	if err != nil {
		return nil, err
	}
	cset := ParseSet{
		Pairs:           make([]PolicyPair, 0),
		IdqlPolicies:    make([]hexapolicy.PolicyInfo, 0),
		Pos:             0,
		loc:             location,
		conditionMapper: c.condMap,
	}

	for _, cedarPolicy := range policies {
		err := cset.MapCedarPolicy(cedarPolicy)
		if err != nil {
			break
		}

	}

	return &hexapolicy.Policies{
		Policies: cset.IdqlPolicies,
		App:      &location,
	}, err

}

func (t *ParseSet) MapCedarPolicy(policy *cedar.Policy) error {
	var err error
	hexaPolicy := hexapolicy.PolicyInfo{Meta: hexapolicy.MetaInfo{Version: hexapolicy.IdqlVersion}}

	jsonBytes, err := policy.MarshalJSON()
	if err != nil {
		return err
	}

	var jsonPolicy policyjson.PolicyJSON

	err = json.Unmarshal(jsonBytes, &jsonPolicy)
	if err != nil {
		return err
	}
	pair := PolicyPair{
		HexaPolicy:  &hexaPolicy,
		CedarPolicy: policy,
		Ast:         jsonPolicy,
	}

	pair.mapCedarAnnotations()
	pair.mapCedarSubject()
	pair.mapCedarAction()
	pair.mapCedarResource()
	err = pair.mapCedarConditions()

	if err != nil {
		return err
	}

	if pair.HexaPolicy != nil {
		t.IdqlPolicies = append(t.IdqlPolicies, *pair.HexaPolicy)
	} else {
		return errors.New("no policy mapped")
	}

	return nil
}

func (c *CedarMapper) MapHexaPolicyBytes(location string, idqlBytes []byte) (string, error) {
	policies, err := hexapolicysupport.ParsePolicies(idqlBytes)
	if err != nil {
		return "", err
	}
	return c.MapHexaPolicies(location, policies)
}

func (c *CedarMapper) MapHexaPolicies(location string, policies []hexapolicy.PolicyInfo) (string, error) {
	sb := strings.Builder{}
	pset := ParseSet{
		Pairs:           make([]PolicyPair, 0),
		IdqlPolicies:    make([]hexapolicy.PolicyInfo, 0),
		Pos:             0,
		loc:             location,
		conditionMapper: c.condMap,
	}

	for _, hexaPolicy := range policies {
		cedarPol, err := pset.MapHexaPolicy(hexaPolicy)
		if err != nil {
			return "", err
		}

		sb.WriteString(cedarPol)

	}

	return sb.String(), nil
}

func (t *ParseSet) MapHexaPolicy(policy hexapolicy.PolicyInfo) (string, error) {
	pp := PolicyPair{
		HexaPolicy: &policy,
		res:        strings.Builder{},
	}

	annotations := pp.mapHexaAnnotations()
	subjects := pp.mapHexaSubjects()
	actions := pp.mapHexaAction()
	resource := pp.mapHexaResource()

	condition, err := t.conditionMapper.MapConditionToCedar(pp.HexaPolicy.Condition)
	if err != nil {
		return "", err
	}

	// conditions ;= pp.mapConditions()
	for _, subject := range subjects {
		pp.writeCedarPolicy(annotations, subject, actions, resource, condition)
	}

	return pp.res.String(), nil
}

func (pp *PolicyPair) writeCedarPolicy(annotations, subject, actions, resource, conditions string) {
	pp.res.WriteString(annotations)
	// Note: IDQL policies are always a permit
	pp.res.WriteString("permit (\n  ")
	pp.res.WriteString(subject)
	pp.res.WriteString("\n  ")
	pp.res.WriteString(actions)
	pp.res.WriteString("\n  ")
	pp.res.WriteString(resource)
	pp.res.WriteString("\n)")
	if conditions != "" {
		pp.res.WriteString("\n")
		pp.res.WriteString(conditions)
	}

	pp.res.WriteString(";\n")

	return
}

// For Hexa, we just map annotations to Policy Meta
func (pp *PolicyPair) mapCedarAnnotations() {
	meta := pp.HexaPolicy.Meta

	annotations := pp.CedarPolicy.Annotations
	aMap := annotations()
	if aMap == nil || len(aMap) == 0 {
		return
	}
	if meta.SourceData == nil {
		meta.SourceData = make(map[string]interface{})
	}
	meta.SourceData["annotations"] = aMap
	pp.HexaPolicy.Meta = meta
}

func (pp *PolicyPair) mapHexaAnnotations() string {
	meta := pp.HexaPolicy.Meta
	sourceData := meta.SourceData
	if sourceData == nil {
		return ""
	}
	annotationMap, ok := sourceData["annotations"].(map[string]interface{})
	if !ok {
		return ""
	}
	sb := strings.Builder{}
	for key, val := range annotationMap {
		sb.WriteString(fmt.Sprintf("@%s(\"%s\")\n", key, val))
	}
	return sb.String()
}

func mapCedarScope(verb string, scope policyjson.ScopeJSON) []string {
	switch scope.Op {
	case "All":
		if verb == "principal" {
			return []string{hexapolicy.SubjectAnyUser}
		}
		return []string{}
	case "==":
		id := scope.Entity.ID.String()
		entityType := string(scope.Entity.Type)
		path := hexaTypes.Entity{
			Type:  hexaTypes.RelTypeEquals,
			Types: []string{entityType},
			Id:    &id,
		}
		return []string{path.String()}
	case "is":
		// This is "principal is User"
		// subj = []string{hexapolicy.SubjectAnyAuth}
		if scope.In != nil {
			// is in

			inEntityStr := fmt.Sprintf("%s:%s", scope.In.Entity.Type, scope.In.Entity.ID)

			inEntity := hexaTypes.ParseEntity(inEntityStr)
			inEntities := []hexaTypes.Entity{*inEntity}
			path := hexaTypes.Entity{
				Type:  hexaTypes.RelTypeIsIn,
				Types: []string{scope.EntityType},
				In:    &inEntities,
			}
			return []string{path.String()}
		} else {
			path := hexaTypes.Entity{
				Type:  hexaTypes.RelTypeIs,
				Types: []string{scope.EntityType}}
			return []string{path.String()}

		}

	case "in":
		if scope.Entity != nil {
			eType := string(scope.Entity.Type)
			id := scope.Entity.ID.String()
			inEntity := hexaTypes.Entity{
				Type:  hexaTypes.RelTypeEquals,
				Types: []string{eType},
				Id:    &id,
			}
			inEntities := []hexaTypes.Entity{inEntity}
			path := hexaTypes.Entity{
				Type: hexaTypes.RelTypeIn,
				In:   &inEntities,
			}
			return []string{path.String()}
		} else {
			items := make([]hexaTypes.Entity, len(scope.Entities))

			for i, entity := range scope.Entities {
				id := entity.ID.String()
				pathItem := hexaTypes.Entity{
					Type:  hexaTypes.RelTypeEquals,
					Id:    &id,
					Types: []string{string(entity.Type)},
				}
				items[i] = pathItem
			}
			if verb == "action" {
				var vals []string
				for _, action := range items {
					vals = append(vals, action.String())
				}
				return vals
			}
			path := hexaTypes.Entity{
				Type: hexaTypes.RelTypeIn,
				In:   &items,
			}
			return []string{path.String()}
		}

	}
	return []string{}
}

func (pp *PolicyPair) mapCedarSubject() {

	principal := pp.Ast.Principal

	subjs := mapCedarScope("principal", principal)
	if len(subjs) == 0 {
		subjs = hexapolicy.SubjectInfo{hexapolicy.SubjectAnyUser}
	}
	pp.HexaPolicy.Subjects = subjs
}

func mapHexaValue(verb string, member string) string {

	if verb == "principal" {
		if strings.EqualFold(member, "any") {
			return "principal,"
		}
		if strings.EqualFold(member, "anyAuthenticated") {
			return "principal is User,"
		}
	}
	comma := ","
	if verb == "resource" {
		comma = ""
	}
	if member == "" {
		return fmt.Sprintf("%s%s", verb, comma)
	}
	path := hexaTypes.ParseEntity(member)
	switch path.Type {
	case hexaTypes.RelTypeEquals:
		types := strings.Join(path.Types, "::")
		id := strconv.Quote(*path.Id)
		if verb == "action" {
			return fmt.Sprintf("%s::%s", types, id)
		}
		return fmt.Sprintf("%s == %s::%s%s", verb, types, id, comma)
	case hexaTypes.RelTypeIs:
		types := strings.Join(path.Types, "::")
		return fmt.Sprintf("%s is %s%s", verb, types, comma)
	case hexaTypes.RelTypeIn:
		if len(*path.In) == 1 {
			// if only one entity, no square brackets
			inset := *path.In
			entity := inset[0]
			types := strings.Join(entity.Types, "::")
			if entity.Id != nil {
				types = types + "::" + strconv.Quote(*entity.Id)
			}
			return fmt.Sprintf("%s in %s%s", verb, types, comma)
		}
		sb := strings.Builder{}
		sb.WriteString("[")
		for i, entity := range *path.In {
			if i > 0 {
				sb.WriteString(",")
			}
			types := strings.Join(entity.Types, "::")
			if entity.Id != nil {
				types = types + "::" + strconv.Quote(*entity.Id)
			}
			sb.WriteString(types)
		}
		sb.WriteString("]")
		return fmt.Sprintf("%s in %s%s", verb, sb.String(), comma)
	case hexaTypes.RelTypeIsIn:
		sb := strings.Builder{}
		if len(*path.In) == 1 {
			// if only one entity, no square brackets
			inset := *path.In
			entity := inset[0]
			types := strings.Join(entity.Types, "::")
			if entity.Id != nil {
				types = types + "::" + strconv.Quote(*entity.Id)
			}
			sb.WriteString(types)
		} else {
			sb.WriteString("[")
			for i, entity := range *path.In {
				if i > 0 {
					sb.WriteString(",")
				}
				types := strings.Join(entity.Types, "::")
				if entity.Id != nil {
					types = types + "::" + strconv.Quote(*entity.Id)
				}
				sb.WriteString(types)
			}
			sb.WriteString("]")
		}
		types := strings.Join(path.Types, "::")
		return fmt.Sprintf("%s is %s in %s%s", verb, types, sb.String(), comma)
	}
	return "<unexpected type [" + path.Type + "]>"
}

func (pp *PolicyPair) mapHexaSubjects() []string {
	if pp.HexaPolicy == nil || pp.HexaPolicy.Subjects == nil {
		return nil
	}
	members := pp.HexaPolicy.Subjects
	if len(members) == 0 || strings.EqualFold(members[0], hexapolicy.SubjectAnyUser) {
		return []string{"principal,"}
	}
	res := make([]string, 0)
	for _, member := range members {
		res = append(res, mapHexaValue("principal", member))
	}
	return res
}

func (pp *PolicyPair) mapCedarAction() {
	action := pp.Ast.Action

	values := mapCedarScope("action", action)

	actions := make([]hexapolicy.ActionInfo, len(values))
	for i, value := range values {
		actions[i] = hexapolicy.ActionInfo(value)
	}
	pp.HexaPolicy.Actions = actions
}

func (pp *PolicyPair) mapHexaAction() string {
	actions := pp.HexaPolicy.Actions
	if actions == nil || len(actions) == 0 {
		return "action,"
	}
	if len(actions) == 1 {
		// if action has a prefix of "Role" then the value is action in xxx
		value := mapHexaValue("action", string(actions[0]))
		return fmt.Sprintf("action == %s,", value)
	}
	var sb strings.Builder
	sb.WriteString("action in [")
	for i, e := range actions {
		if i > 0 {
			sb.WriteString(",")
		}

		sb.WriteString(mapHexaValue("action", string(e)))
	}
	sb.WriteString("],")
	return sb.String()
}

func (pp *PolicyPair) mapCedarResource() {
	resource := pp.Ast.Resource

	values := mapCedarScope("resource", resource)
	if values == nil || len(values) == 0 {
		pp.HexaPolicy.Object = ""
	} else {
		pp.HexaPolicy.Object = hexapolicy.ObjectInfo(values[0])
	}

}

func (pp *PolicyPair) mapHexaResource() string {
	resource := pp.HexaPolicy.Object.String()

	return mapHexaValue("resource", resource)

}

func (pp *PolicyPair) mapCedarConditions() error {
	hexaCondition, err := cedarConditions.MapCedarConditionToHexa(pp.Ast.Conditions)
	if hexaCondition != nil {
		pp.HexaPolicy.Condition = hexaCondition
	}
	return err
}
