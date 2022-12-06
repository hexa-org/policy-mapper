package filter

import "fmt"

const (
	// PR is an abbreviation for 'present'.
	PR CompareOperator = "pr"
	// EQ is an abbreviation for 'equals'.
	EQ CompareOperator = "eq"
	// NE is an abbreviation for 'not equals'.
	NE CompareOperator = "ne"
	// CO is an abbreviation for 'contains'.
	CO CompareOperator = "co"
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

	// AND is the logical operation and (&&).
	AND LogicalOperator = "and"
	// OR is the logical operation or (||).
	OR LogicalOperator = "or"

	OPEN LogicalOperator = "("
)

type CompareOperator string

type LogicalOperator string

type Expression interface {
	exprNode()
	String() string
}

type LogicalExpression struct {
	Operator    LogicalOperator
	Left, Right Expression
}

func (LogicalExpression) exprNode() {}
func (e LogicalExpression) String() string {
	return fmt.Sprintf("%s %s %s", e.Left.String(), e.Operator, e.Right.String())
}

type NotExpression struct {
	Expression Expression
}

func (e NotExpression) String() string {
	return fmt.Sprintf("not (%s)", e.Expression.String())
}

func (NotExpression) exprNode() {}

type PrecedenceExpression struct {
	Expression Expression
}

func (PrecedenceExpression) exprNode() {}

func (e PrecedenceExpression) String() string {
	return fmt.Sprintf("(%s)", e.Expression.String())
}

type AttributeExpression struct {
	Attribute string
	Op        CompareOperator
	Value     interface{}
}

func (AttributeExpression) exprNode() {}

func (e AttributeExpression) String() string {
	if e.Op == "pr" {
		return fmt.Sprintf("%s pr", e.Attribute)
	}
	switch e.Value.(type) {
	case string:
		return fmt.Sprintf("%s %s \"%s\"", e.Attribute, e.Op, e.Value.(string))
	default:
		return fmt.Sprintf("%s %s %v", e.Attribute, e.Op, e.Value)
	}

}

type ValuePathExpression struct {
	Attribute   string
	VPathFilter Expression
}

func (ValuePathExpression) exprNode() {}
func (e ValuePathExpression) String() string {
	return fmt.Sprintf("%s[%s]", e.Attribute, e.VPathFilter.String())
}
