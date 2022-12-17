package conditions

import (
	"errors"
	"fmt"
	"policy-conditions/policySupport/filter"

	"strings"
)

type ConditionInfo struct {
	Rule   string `json:"rule" validate:"required"` // in RFC7644 filter form
	Action string `json:"action"`                   // allow/deny/audit default is allow
}

type AttributeMap struct {
	forward map[string]string
	reverse map[string]string
}

type NameMapper interface {
	// GetProviderAttributeName returns a simple string representation of the mapped attribute name (usually in name[.sub-attribute] form).
	GetProviderAttributeName(hexaName string) string

	// GetHexaFilterAttributePath returns a filterAttributePath which is used to build a SCIM Filter AST
	GetHexaFilterAttributePath(provName string) string
}

type ConditionMapper interface {
	/*
		MapConditionToProvider takes an IDQL Condition expression and converts it to a string
		usable the target provider. For example from RFC7644, Section-3.4.2.2 to Google Common Expression Language
	*/
	MapConditionToProvider(condition ConditionInfo) interface{}

	/*
		MapProviderToCondition take a string expression from a platform policy and converts it to RFC7644: Section-3.4.2.2.
	*/
	MapProviderToCondition(expression string) (ConditionInfo, error)
}

// NewNameMapper is called by a condition mapper provider to instantiate an attribute name translator using interface NameMapper
func NewNameMapper(attributeMap map[string]string) *AttributeMap {
	reverse := make(map[string]string, len(attributeMap))
	forward := make(map[string]string, len(attributeMap))
	for k, v := range attributeMap {
		reverse[strings.ToLower(v)] = k
		forward[strings.ToLower(k)] = v
	}

	return &AttributeMap{
		forward: forward,
		reverse: reverse,
	}
}

func (n *AttributeMap) GetProviderAttributeName(hexaName string) string {
	val, exists := n.forward[strings.ToLower(hexaName)]
	if exists {
		return val
	}
	return hexaName
}

func (n *AttributeMap) GetHexaFilterAttributePath(provName string) string {
	val, exists := n.reverse[provName]
	if !exists {
		val = provName
	}
	return val
}

// ParseConditionRuleAst is used by mapping providers to get the IDQL condition rule AST tree
func ParseConditionRuleAst(condition ConditionInfo) (*filter.Expression, error) {
	return filter.ParseFilter(condition.Rule)
}

func ParseExpressionAst(expression string) (*filter.Expression, error) {
	return filter.ParseFilter(expression)
}

// SerializeExpression walks the AST and emits the condition in string form. It preserves precedence over the normal filter.String() method
func SerializeExpression(ast *filter.Expression) (string, error) {

	return walk(*ast, false)
}

func checkRepeatLogic(e filter.Expression, op filter.LogicalOperator) (string, error) {
	// if the child is a repeat of the parent eliminate brackets (e.g. a or b or c)

	switch v := interface{}(e).(type) {
	case filter.LogicalExpression:
		if v.Operator == op {
			return walk(e, false)
		} else {
			return walk(e, true)
		}
	default:
		return walk(e, true)
	}
}

func walk(e filter.Expression, isChild bool) (string, error) {
	switch v := e.(type) {
	case filter.LogicalExpression:
		lhVal, err := checkRepeatLogic(v.Left, v.Operator)
		if err != nil {
			return "", err
		}
		rhVal, err := checkRepeatLogic(v.Right, v.Operator)
		if err != nil {
			return "", err
		}
		if isChild && v.Operator == filter.OR {
			return fmt.Sprintf("(%v or %v)", lhVal, rhVal), nil
		} else {
			return fmt.Sprintf("%v %v %v", lhVal, v.Operator, rhVal), nil
		}
	case filter.NotExpression:
		subExpression := v.Expression
		// Note, because of not() brackets, can treat as top level
		subExpressionString, err := walk(subExpression, false)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("not(%v)", subExpressionString), nil

	case filter.ValuePathExpression:
		return walk(v.VPathFilter, true)
	case filter.AttributeExpression:
		return v.String(), nil
	}

	errMsg := fmt.Sprintf("idql evaluator: Unimplemented filter expression: %v", e)
	return "", errors.New(errMsg)
}
