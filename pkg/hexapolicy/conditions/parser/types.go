package parser

import (
    "fmt"
    "regexp"
    "strings"
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
    AttributePath string
    Operator      CompareOperator
    CompareValue  string
}

func (AttributeExpression) exprNode() {}

func (e AttributeExpression) String() string {
    if e.Operator == "pr" {
        return fmt.Sprintf("%s pr", e.AttributePath)
    }

    isNumber, _ := regexp.MatchString("^[-+]?[0-9]+[.]?[0-9]*([eE][-+]?[0-9]+)?$", e.CompareValue)
    if isNumber {
        // Numbers are not quoted
        return fmt.Sprintf("%s %s %v", e.AttributePath, e.Operator, e.CompareValue)
    }

    // Check boolean
    lVal := strings.ToLower(e.CompareValue)
    if lVal == "true" || lVal == "false" {
        return fmt.Sprintf("%s %s %v", e.AttributePath, e.Operator, lVal)
    }

    // treat as string
    comp := e.CompareValue

    // Do not quote if value is already quoted or doesn't have a space
    if strings.Contains(comp, "\"") || !strings.Contains(comp, " ") {
        return fmt.Sprintf("%s %s %s", e.AttributePath, e.Operator, e.CompareValue)
    }
    return fmt.Sprintf("%s %s \"%s\"", e.AttributePath, e.Operator, e.CompareValue)
}

func (e AttributeExpression) Dif() string {
    return e.String()
}

type ValuePathExpression struct {
    Attribute   string
    VPathFilter Expression
}

func (ValuePathExpression) exprNode() {}
func (e ValuePathExpression) String() string {
    return fmt.Sprintf("%s[%s]", e.Attribute, e.VPathFilter.String())
}
func (e ValuePathExpression) Dif() string { return e.String() }
