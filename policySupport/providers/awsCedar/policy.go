package awsCedar

import (
	"github.com/alecthomas/participle/v2"
	policySupport "github.com/hexa-org/policy-mapper/policySupport"
	policyCond "github.com/hexa-org/policy-mapper/policySupport/conditions"
	"os"

	"github.com/hexa-org/policy-mapper/policySupport/conditions/googleCel"
	"strings"
)

type CedarPolicyMapper struct {
	conditionMapper googleCel.GoogleConditionMapper
	parser          *participle.Parser[CedarPolicies]
}

func New(nameMap map[string]string) *CedarPolicyMapper {
	return &CedarPolicyMapper{conditionMapper: googleCel.GoogleConditionMapper{NameMapper: policyCond.NewNameMapper(nameMap)},
		parser: participle.MustBuild[CedarPolicies](participle.CaseInsensitive("permit", "forbid", "unless", "when"))}
}

func (c *CedarPolicyMapper) ParseCedarBytes(cedarBytes []byte) (*CedarPolicies, error) {
	cedarAst, err := c.parser.ParseBytes("", cedarBytes)
	return cedarAst, err
}

/*
MapPolicyToCedar takes an IDQL Policy and maps it to 1 or more Cedar policies. The need for more than one arises because
IDQL supports multiple subjects where Cedar is limited to 1 Principal and 1 Resource.
*/
func (c *CedarPolicyMapper) MapPolicyToCedar(idqlPol policySupport.PolicyInfo) ([]*CedarPolicy, error) {
	cpolicies := make([]*CedarPolicy, 0)

	if len(idqlPol.Subject.Members) == 0 {
		cpolicy, err := c.mapSimplePolicyToCedar("", idqlPol)
		if err != nil {
			return nil, err
		}
		cpolicies = append(cpolicies, cpolicy)

		return cpolicies, nil
	}

	for _, v := range idqlPol.Subject.Members {
		cpolicy, err := c.mapSimplePolicyToCedar(v, idqlPol)
		if err != nil {
			return nil, err
		}
		cpolicies = append(cpolicies, cpolicy)
	}
	return cpolicies, nil
}

func mapActionItemToUri(cedarAction string) string {
	ret := cedarAction
	if strings.Contains(cedarAction, "::") {
		ret = "cedar:" + cedarAction
	}
	return ret
}

func mapActionUri(idqlaction string) string {
	ret := idqlaction
	if strings.HasPrefix(strings.ToLower(idqlaction), "cedar:") {
		ret = idqlaction[6:]
	}
	return ret
}

func (c *CedarPolicyMapper) mapActions(actions []policySupport.ActionInfo) *ActionExpression {
	switch len(actions) {
	case 0:
		return nil
	case 1:
		action := mapActionUri(actions[0].ActionUri)

		return &ActionExpression{
			Operator: EQUALS,
			Action:   action,
		}

	default:
		cActions := make([]ActionItem, len(actions))
		for k, v := range actions {
			actionIden := mapActionUri(v.ActionUri)
			cActions[k].Item = actionIden
		}
		return &ActionExpression{
			Operator: IN,
			Actions:  cActions,
		}
	}
}

func isSingular(entityId string) bool {
	var singleResources = []string{"file", "user", "employee"}
	lEntityId := strings.ToLower(entityId)
	for _, v := range singleResources {
		if strings.HasPrefix(lEntityId, v) {
			return true
		}
	}
	return false
}

func mapResourceToObject(res *ResourceExpression) policySupport.ObjectInfo {
	mId := "cedar:" + res.Entity
	return policySupport.ObjectInfo{
		ResourceID: mId,
	}
}

func mapObjectToResource(object policySupport.ObjectInfo) *ResourceExpression {
	id := object.ResourceID
	if id == "" {
		return nil
	}
	op := IN
	if isSingular(id) {
		op = EQUALS
	}

	mId := id
	if strings.HasPrefix(strings.ToLower(id), "cedar:") {
		mId = id[6:]
	}
	return &ResourceExpression{
		Operator: op,
		Entity:   mId,
	}
}

func mapMemberToPrincipal(member string) string {
	parts := strings.SplitN(member, ":", 2)
	if len(parts) == 1 {
		return member
	}
	if strings.HasPrefix(parts[1], ":") {
		return member
	}
	return parts[0] + "::" + parts[1]
}

func mapPrincipalToMember(principal string) string {
	parts := strings.SplitN(principal, "::", 2)
	if len(parts) == 1 {
		return principal
	}

	return parts[0] + ":" + parts[1]
}

func (c *CedarPolicyMapper) mapSimplePolicyToCedar(member string, policy policySupport.PolicyInfo) (*CedarPolicy, error) {
	var conds []*ConditionalClause
	if policy.Condition != nil {
		operator := WHEN
		if policy.Condition.Action == "deny" {
			operator = UNLESS
		}
		cel, err := c.conditionMapper.MapConditionToProvider(*policy.Condition)
		if err != nil {
			return nil, err
		}
		var cond = ConditionType(cel)
		conds = append(conds, &ConditionalClause{
			Type:      operator,
			Condition: &cond,
		})
	}

	var principal *PrincipalExpression
	switch member {
	case policySupport.SAnyUser, "":
		principal = nil

	case policySupport.SAnyAuth, policySupport.SJwtAuth, policySupport.SSamlAuth, policySupport.SBasicAuth:
		principal = nil
		cond := ConditionType("context.authenticated == true")
		conds = append(conds, &ConditionalClause{
			Type:      WHEN,
			Condition: &cond})
	default:
		princ := mapMemberToPrincipal(member)
		lMember := strings.ToLower(member)
		switch lMember[0:4] {
		case "user:":
			principal = &PrincipalExpression{
				Operator: "==",
				Entity:   princ,
			}
		case "group", "domai":
			principal = &PrincipalExpression{
				Operator: "in",
				Entity:   princ,
			}

		default:
			// For now assume all other types are singular so ==
			principal = &PrincipalExpression{
				Operator: "==",
				Entity:   princ,
			}

		}
	}

	actions := c.mapActions(policy.Actions)
	res := mapObjectToResource(policy.Object)

	head := PolicyHead{
		Principal: principal,
		Actions:   actions,
		Resource:  res,
	}

	return &CedarPolicy{
		Type:       PERMIT,
		Head:       &head,
		Conditions: conds,
	}, nil
}

func (c *CedarPolicyMapper) MapPoliciesToCedar(policies []policySupport.PolicyInfo) (*CedarPolicies, error) {
	cpolicies := make([]*CedarPolicy, 0)
	for _, v := range policies {
		newPols, err := c.MapPolicyToCedar(v)
		if err != nil {
			return nil, err
		}
		cpolicies = append(cpolicies, newPols...)
	}

	return &CedarPolicies{
		Policies: cpolicies,
	}, nil
}

func (c *CedarPolicyMapper) MapCedarPolicyToIdql(policy *CedarPolicy) (*policySupport.PolicyInfo, error) {

	var subj policySupport.SubjectInfo
	if policy.Head.Principal == nil {
		subj = policySupport.SubjectInfo{Members: []string{policySupport.SAnyUser}}
	} else {
		subj = policySupport.SubjectInfo{Members: []string{mapPrincipalToMember(policy.Head.Principal.Entity)}}
	}

	actions := make([]policySupport.ActionInfo, 0)
	if policy.Head.Actions != nil {
		if policy.Head.Actions.Action != "" {
			actions = append(actions, policySupport.ActionInfo{ActionUri: mapActionItemToUri(policy.Head.Actions.Action)})
		} else {
			for _, v := range policy.Head.Actions.Actions {
				actions = append(actions, policySupport.ActionInfo{ActionUri: mapActionItemToUri(v.Item)})
			}
		}
	}

	conditions := make([]string, 0)
	for _, v := range policy.Conditions {
		cel := string(*v.Condition)
		// cel mapper won't tolerate ::
		if strings.Contains(cel, "::") {
			cel = strings.ReplaceAll(cel, "Group::\"", "\"Group:")
			cel = strings.ReplaceAll(cel, "User::\"", "\"User:")
			cel = strings.ReplaceAll(cel, "Account::\"", "\"Account:")
			cel = strings.ReplaceAll(cel, "Domain::\"", "\"Domain:")
			//cel = strings.ReplaceAll(cel, " in ", " co ") // this is just temporary
		}

		idqlCond, err := c.conditionMapper.MapProviderToCondition(cel)
		if err != nil {
			return nil, err
		}

		if v.Type == WHEN {
			conditions = append(conditions, idqlCond.Rule)
		} else {
			conditions = append(conditions, "not("+idqlCond.Rule+")")
		}
	}

	var condInfo *policyCond.ConditionInfo
	if len(conditions) == 0 {
		condInfo = nil
	} else {
		if len(conditions) == 1 {
			condInfo = &policyCond.ConditionInfo{
				Rule:   conditions[0],
				Action: PERMIT,
			}
		} else {
			merge := ""
			for i, v := range conditions {
				if i == 0 {
					merge = "(" + v + ")"
				} else {
					if strings.HasPrefix(v, "not") {
						merge = merge + " && " + v
					} else {
						merge = merge + " && (" + v + ")"

					}
				}
			}
			condInfo = &policyCond.ConditionInfo{
				Rule:   merge,
				Action: PERMIT,
			}
		}
	}
	obj := policySupport.ObjectInfo{}
	if policy.Head.Resource != nil {
		obj = mapResourceToObject(policy.Head.Resource)
	}
	ret := policySupport.PolicyInfo{
		Meta:      policySupport.MetaInfo{Version: "0.5"},
		Actions:   actions,
		Subject:   subj,
		Object:    obj,
		Condition: condInfo,
	}
	return &ret, nil
}

func (c *CedarPolicyMapper) MapCedarPoliciesToIdql(cedarPols *CedarPolicies) (*policySupport.Policies, error) {
	pols := make([]policySupport.PolicyInfo, 0)

	for _, v := range cedarPols.Policies {
		mapPol, err := c.MapCedarPolicyToIdql(v)
		if err != nil {
			return nil, err
		}
		pols = append(pols, *mapPol)
	}
	return &policySupport.Policies{Policies: pols}, nil
}

func (c *CedarPolicyMapper) ParseFile(filename string) (*policySupport.Policies, error) {
	policyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return c.ParseAndMapCedarToHexa(policyBytes)
}

func (c *CedarPolicyMapper) ParseAndMapCedarToHexa(cedarBytes []byte) (*policySupport.Policies, error) {

	cedarPols, err := c.ParseCedarBytes(cedarBytes)
	if err != nil {
		return nil, err
	}

	return c.MapCedarPoliciesToIdql(cedarPols)
}
