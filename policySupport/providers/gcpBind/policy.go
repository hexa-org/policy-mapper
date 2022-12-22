package gcpBind

import (
	"encoding/json"
	"fmt"
	"google.golang.org/api/iam/v1"
	"os"
	policysupport "policy-conditions/policySupport"
	"policy-conditions/policySupport/conditions"
	"policy-conditions/policySupport/conditions/googleCel"
	"strings"
)

type GooglePolicyMapper struct {
	conditionMapper googleCel.GoogleConditionMapper
}

type GcpBindAssignment struct {
	ResourceId string        `json:"resource_id"`
	Bindings   []iam.Binding `json:"bindings"`
}

func New(nameMap map[string]string) *GooglePolicyMapper {
	return &GooglePolicyMapper{conditionMapper: googleCel.GoogleConditionMapper{NameMapper: conditions.NewNameMapper(nameMap)}}
}

func (m *GooglePolicyMapper) MapBindingAssignmentsToPolicy(bindAssignments []GcpBindAssignment) ([]policysupport.PolicyInfo, error) {
	var policies []policysupport.PolicyInfo
	for _, v := range bindAssignments {
		pols, err := m.MapBindingAssignmentToPolicy(v)
		if err != nil {
			return nil, err
		}
		for _, pol := range pols {
			policies = append(policies, pol)
		}
	}
	return policies, nil
}

func (m *GooglePolicyMapper) MapBindingAssignmentToPolicy(bindAssignment GcpBindAssignment) ([]policysupport.PolicyInfo, error) {
	var policies []policysupport.PolicyInfo
	objectId := bindAssignment.ResourceId
	for _, v := range bindAssignment.Bindings {
		policy, err := m.MapBindingToPolicy(objectId, v)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

func (m *GooglePolicyMapper) MapBindingToPolicy(objectId string, binding iam.Binding) (policysupport.PolicyInfo, error) {
	bindingCondition := binding.Condition
	if bindingCondition != nil {
		condition, err := m.convertCelToCondition(binding.Condition)
		if err != nil {
			return policysupport.PolicyInfo{}, err
		}

		policy := policysupport.PolicyInfo{
			Meta:      policysupport.MetaInfo{Version: "0.5"},
			Actions:   convertRoleToAction(binding.Role),
			Subject:   policysupport.SubjectInfo{Members: binding.Members},
			Object:    policysupport.ObjectInfo{ResourceID: objectId},
			Condition: condition,
		}
		return policy, nil
	}
	policy := policysupport.PolicyInfo{
		Meta:    policysupport.MetaInfo{Version: "0.5"},
		Actions: convertRoleToAction(binding.Role),
		Subject: policysupport.SubjectInfo{Members: binding.Members},
		Object:  policysupport.ObjectInfo{ResourceID: objectId},
	}
	return policy, nil

}

func (m *GooglePolicyMapper) MapPolicyToBinding(policy policysupport.PolicyInfo) (*iam.Binding, error) {
	cond := policy.Condition
	var condExpr *iam.Expr
	var err error
	if cond.Rule != "" {
		condExpr, err = m.convertPolicyCondition(policy)
	} else {
		condExpr = nil
	}

	if err != nil {
		return nil, err
	}
	return &iam.Binding{
		Condition: condExpr,
		Members:   policy.Subject.Members,
		Role:      convertActionToRole(policy),
	}, nil
}

func (m *GooglePolicyMapper) MapPoliciesToBindings(policies []policysupport.PolicyInfo) []*GcpBindAssignment {
	bindingMap := make(map[string][]iam.Binding)

	for i, policy := range policies {
		binding, err := m.MapPolicyToBinding(policy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			continue
		}
		key := policies[i].Object.ResourceID

		existing := bindingMap[key]
		existing = append(existing, *binding)
		bindingMap[key] = existing

	}
	bindings := make([]*GcpBindAssignment, len(bindingMap))
	i := 0
	for k, v := range bindingMap {
		bindings[i] = &GcpBindAssignment{
			ResourceId: k,
			Bindings:   v,
		}
		i++
	}
	return bindings
}

func convertActionToRole(policy policysupport.PolicyInfo) string {
	for _, v := range policy.Actions {
		action := v.ActionUri
		if strings.HasPrefix(action, "gcp:") {
			return action[4:]
		}
	}
	return ""
}

func convertRoleToAction(role string) []policysupport.ActionInfo {
	if role == "" {
		return nil
	}
	return []policysupport.ActionInfo{{"gcp:" + role}}
}

func (m *GooglePolicyMapper) convertCelToCondition(expr *iam.Expr) (conditions.ConditionInfo, error) {
	return m.conditionMapper.MapProviderToCondition(expr.Expression)
}

func (m *GooglePolicyMapper) convertPolicyCondition(policy policysupport.PolicyInfo) (*iam.Expr, error) {
	if policy.Condition.Rule == "" {
		return nil, nil // do nothing as policy has no condition
	}

	celString, err := m.conditionMapper.MapConditionToProvider(policy.Condition)
	if err != nil {
		return nil, err
	}

	iamExpr := iam.Expr{
		Expression: celString,
	}
	return &iamExpr, nil
}

/*
ParseBindings will read either an iam.Binding or GcpBindAssignment structure and returns a []*GcpBindAssignment type.
Note that if a single binding is provided, the GcpBindAssignment.ResourceId value will be nil
*/
func ParseBindings(bindingBytes []byte) ([]GcpBindAssignment, error) {
	var bindAssign []GcpBindAssignment
	err := json.Unmarshal(bindingBytes, &bindAssign)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "[]gcpBind.GcpBindAssignment") {
			// Try GcpBindAssignment
			var single GcpBindAssignment
			errGcp := json.Unmarshal(bindingBytes, &single)
			if errGcp != nil {
				return nil, errGcp
			}
			if single.ResourceId == "" {
				// Try iam.Binding
				var binding iam.Binding
				err3 := json.Unmarshal(bindingBytes, &binding)
				if err3 != nil {
					return nil, err3
				} else {
					bindings := make([]iam.Binding, 1)
					bindings[0] = binding
					bindAssign = append(bindAssign, GcpBindAssignment{Bindings: bindings})
				}

			} else {
				bindAssign = append(bindAssign, single)
			}

		}
	}

	return bindAssign, nil

}

/*
ParseFile will load a file from the specified path and will auto-detect format and convert to GcpBindAssignment. See ParseBindings
*/
func ParseFile(path string) ([]GcpBindAssignment, error) {
	policyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseBindings(policyBytes)
}
