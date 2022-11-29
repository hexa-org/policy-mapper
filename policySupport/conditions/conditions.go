package conditions

import (
	"errors"
	"fmt"
	"github.com/scim2/filter-parser/v2"
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
	GetHexaFilterAttributePath(provName string) filter.AttributePath
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

func nameToAttributePath(name string) filter.AttributePath {
	if strings.Contains(name, ".") {
		parts := strings.Split(name, ".")
		return filter.AttributePath{AttributeName: parts[0],
			SubAttribute: &parts[1]}
	}
	return filter.AttributePath{AttributeName: name}
}

func (n *AttributeMap) GetHexaFilterAttributePath(provName string) filter.AttributePath {
	val, exists := n.reverse[provName]
	if !exists {
		val = provName
	}
	return nameToAttributePath(val)
}

// ParseConditionRuleAst is used by mapping providers to get the IDQL condition rule AST tree
func ParseConditionRuleAst(condition ConditionInfo) (filter.Expression, error) {
	return filter.ParseFilter([]byte(condition.Rule))
}

// SerializeExpression walks the AST and emits the condition in string form. It preserves precedence over the normal filter.String() method
func SerializeExpression(ast filter.Expression) (string, error) {

	return walk(ast, false)
}

func walk(e filter.Expression, isChild bool) (string, error) {
	switch v := e.(type) {
	case *filter.LogicalExpression:
		lhVal, err := walk(v.Left, true)
		rhVal, err := walk(v.Right, true)
		if err != nil {
			return "", err
		}
		if isChild && v.Operator == filter.OR {
			return fmt.Sprintf("(%v %v %v)", lhVal, v.Operator, rhVal), nil
		} else {
			return fmt.Sprintf("%v %v %v", lhVal, v.Operator, rhVal), nil
		}
	case *filter.NotExpression:
		subExpression := v.Expression
		// Note, because of not() brackets, can treat as top level
		subExpressionString, err := walk(subExpression, true)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("not(%v)", subExpressionString), nil

	case *filter.ValuePath:
		return walk(v.ValueFilter, true)
	case *filter.AttributeExpression:
		return fmt.Sprintf("%s %s %q", v.AttributePath, v.Operator, v.CompareValue), nil
	default:
		// etc...
	}

	errMsg := fmt.Sprintf("Unimplemented filter expression: %v", e)
	return "", errors.New(errMsg)
}
