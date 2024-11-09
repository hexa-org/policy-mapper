package parser

import (
	"fmt"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/types"
)

const (
	// PR is an abbreviation for 'present'.
	PR CompareOperator = "pr"
	// EQ is an abbreviation for 'equals'.
	EQ CompareOperator = "eq"
	// NE is an abbreviation for 'not equals'.
	NE CompareOperator = "ne"
	// CO is an abbreviation for 'contains'.
	CO CompareOperator = "co"
	// IN is an abbreviation for 'in'.
	IN CompareOperator = "in"
	// SW is an abbreviation for 'starts with'.
	SW CompareOperator = "sw"
	// EW an abbreviation for 'ends with'.
	EW CompareOperator = "ew"
	// GT is an abbreviation for 'greater than'.
	GT CompareOperator = "gt"
	// LT is an abbreviation for 'less than'.
	LT CompareOperator = "lt"
	// GE is an abbreviation for 'greater or equal than'.
	GE CompareOperator = "ge"
	// LE is an abbreviation for 'less or equal than'.
	LE CompareOperator = "le"

	// IS allows comparison of Object/Resource Types - added for Cedar compat
	IS CompareOperator = "is"

	// AND is the logical operation and (&&).
	AND LogicalOperator = "and"
	// OR is the logical operation or (||).
	OR LogicalOperator = "or"
)

type CompareOperator string

type LogicalOperator string

type Expression interface {
	exprNode()
	String() string
	Dif() string
}

type LogicalExpression struct {
	Operator    LogicalOperator
	Left, Right Expression
}

func (LogicalExpression) exprNode() {}

func (e LogicalExpression) String() string {
	return fmt.Sprintf("%s %s %s", e.Left.String(), e.Operator, e.Right.String())
}
func (e LogicalExpression) Dif() string {
	return string(e.Operator)
}

type NotExpression struct {
	Expression Expression
}

func (e NotExpression) String() string {
	return fmt.Sprintf("not (%s)", e.Expression.String())
}

func (NotExpression) exprNode() {}

func (e NotExpression) Dif() string {

	switch exp := e.Expression.(type) {
	case AttributeExpression, ValuePathExpression:
		return fmt.Sprintf("not(%s)", exp.String())
	default:
		return "not"
	}
}

type PrecedenceExpression struct {
	Expression Expression
}

func (PrecedenceExpression) exprNode() {}

func (e PrecedenceExpression) String() string {
	return fmt.Sprintf("(%s)", e.Expression.String())
}

func (PrecedenceExpression) Dif() string {
	return ""
}

type AttributeExpression struct {
	AttributePath types.Value
	Operator      CompareOperator
	CompareValue  types.Value
}

func NewAttributeExpression(attributePath string, operator CompareOperator, compareValue string) (Expression, error) {
	left, err := types.ParseValue(attributePath)
	if err != nil {
		return nil, err
	}
	var right types.Value
	if operator != PR {
		right, err = types.ParseValue(compareValue)
		if err != nil {
			return nil, err
		}
	}

	return AttributeExpression{
		AttributePath: left,
		Operator:      operator,
		CompareValue:  right,
	}, nil
}

// GetEntityPaths checks AttributePath and CompareValue operands to see if an
// attribute is detected. If detected, the parsed Entity value is returned for the operand
func (e AttributeExpression) GetEntityPaths() []types.Entity {
	var paths []types.Entity
	if e.AttributePath.ValueType() == types.TypeVariable {
		paths = append(paths, e.AttributePath.(types.Entity))
	}
	if e.CompareValue.ValueType() == types.TypeVariable {
		paths = append(paths, e.CompareValue.(types.Entity))
	}
	return paths
}

func (AttributeExpression) exprNode() {}

func (e AttributeExpression) String() string {
	if e.Operator == "pr" {
		return fmt.Sprintf("%s pr", e.AttributePath.String())
	}

	return fmt.Sprintf("%s %s %s", e.AttributePath.String(), e.Operator, e.CompareValue.String())

}

func (e AttributeExpression) Dif() string {
	return e.String()
}

type ValuePathExpression struct {
	Attribute    types.Entity
	SubAttr      *string
	VPathFilter  Expression
	Operator     *CompareOperator
	CompareValue types.Value
}

// GetEntityPaths checks AttributePath and CompareValue operands to see if an
// attribute is detected. If detected, the parsed Entity value is returned for the operand
func (e ValuePathExpression) GetEntityPaths() []types.Entity {
	var paths []types.Entity

	paths = append(paths, e.Attribute)

	if e.CompareValue.ValueType() == types.TypeVariable {
		paths = append(paths, e.CompareValue.(types.Entity))
	}
	return paths
}

func (ValuePathExpression) exprNode() {}
func (e ValuePathExpression) String() string {
	var attrString string
	if e.SubAttr != nil {
		attrString = fmt.Sprintf("%s[%s].%s", e.Attribute.String(), e.VPathFilter.String(), *e.SubAttr)
	} else {
		attrString = fmt.Sprintf("%s[%s]", e.Attribute.String(), e.VPathFilter.String())
	}

	if e.Operator == nil {
		return attrString
	}

	if *e.Operator == "pr" {
		return fmt.Sprintf("%s pr", attrString)
	}

	return fmt.Sprintf("%s %s %s", attrString, *e.Operator, e.CompareValue.String())
}

func (e ValuePathExpression) Dif() string { return e.String() }
