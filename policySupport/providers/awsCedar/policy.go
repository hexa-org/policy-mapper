package awsCedar

import (
	"github.com/alecthomas/participle/v2"
	policySupport "policy-conditions/policySupport"
	"policy-conditions/policySupport/conditions"

	"policy-conditions/policySupport/conditions/googleCel"
	"strings"
)

type CedarPolicyMapper struct {
	conditionMapper googleCel.GoogleConditionMapper
	parser          *participle.Parser[CedarPolicies]
}

func New(nameMap map[string]string) *CedarPolicyMapper {
	return &CedarPolicyMapper{conditionMapper: googleCel.GoogleConditionMapper{NameMapper: conditions.NewNameMapper(nameMap)},
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
func (a *CedarPolicyMapper) MapPolicyToCedar(idqlPol policySupport.PolicyInfo) ([]*CedarPolicy, error) {
	cpolicies := make([]*CedarPolicy, 0)

	if len(idqlPol.Subject.Members) == 0 {
		cpolicy, err := a.mapSimplePolicyToCedar("", idqlPol)
		if err != nil {
			return nil, err
		}
		cpolicies = append(cpolicies, cpolicy)

		return cpolicies, nil
	}

	for _, v := range idqlPol.Subject.Members {
		cpolicy, err := a.mapSimplePolicyToCedar(v, idqlPol)
		if err != nil {
			return nil, err
		}
		cpolicies = append(cpolicies, cpolicy)
	}
	return cpolicies, nil
}

func mapActionUri(idqlaction string) string {
	ret := idqlaction
	if strings.HasPrefix(strings.ToLower(idqlaction), "cedar:") {
		ret = idqlaction[6:]
	}
	return ret
}

func (a *CedarPolicyMapper) mapActions(actions []policySupport.ActionInfo) *ActionExpression {
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

func (a *CedarPolicyMapper) mapObjectToResource(object policySupport.ObjectInfo) *ResourceExpression {
	id := object.ResourceID
	op := IN
	if isSingular(id) {
		op = EQUALS
	}

	return &ResourceExpression{
		Operator: op,
		Entity:   id,
	}
}

func (a *CedarPolicyMapper) mapSimplePolicyToCedar(member string, policy policySupport.PolicyInfo) (*CedarPolicy, error) {
	var conds []*ConditionalClause
	if policy.Condition != nil {
		operator := WHEN
		if policy.Condition.Action == "deny" {
			operator = UNLESS
		}
		cel, err := a.conditionMapper.MapConditionToProvider(*policy.Condition)
		if err != nil {
			return nil, err
		}
		var cond ConditionType = ConditionType(cel)
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
		lMember := strings.ToLower(member)
		switch lMember[0:4] {
		case "user:":
			principal = &PrincipalExpression{
				Operator: "==",
				Entity:   member,
			}
		case "group", "domai":
			principal = &PrincipalExpression{
				Operator: "in",
				Entity:   member,
			}

		default:
			// For now assume all other types are singular so ==
			principal = &PrincipalExpression{
				Operator: "==",
				Entity:   member,
			}

		}
	}

	actions := a.mapActions(policy.Actions)
	res := a.mapObjectToResource(policy.Object)
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

func (a *CedarPolicyMapper) MapPoliciesToCedar(policies []policySupport.PolicyInfo) (*CedarPolicies, error) {
	cpolicies := make([]*CedarPolicy, 0)
	for _, v := range policies {
		newPols, err := a.MapPolicyToCedar(v)
		if err != nil {
			return nil, err
		}
		cpolicies = append(cpolicies, newPols...)
	}

	return &CedarPolicies{
		Policies: cpolicies,
	}, nil
}
