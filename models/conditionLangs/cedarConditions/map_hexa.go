package cedarConditions

import (
    "errors"
    "fmt"
    "strconv"
    "strings"

    "github.com/cedar-policy/cedar-go/types"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
    hexaParser "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions/parser"
)

type CedarConditionMapper struct {
    NameMapper *conditions.AttributeMap
}

// MultiLogicalExpression is used to flatten an inbound IDQL statement in cases where there are ands with more than 2 values
type MultiLogicalExpression struct {
    Operator    hexaParser.LogicalOperator
    Expressions []Expression
}

type Expression interface {
    String() string
}

func (m *MultiLogicalExpression) exprNode() {}

func (m *MultiLogicalExpression) String() string {
    return ""
}

func makeFlattenedLogical(logical hexaParser.LogicalExpression) Expression {
    res := MultiLogicalExpression{}
    res.Operator = logical.Operator
    res.flatten(logical)
    return &res
}

func (m *MultiLogicalExpression) flatten(logical hexaParser.LogicalExpression) {

    switch exp := logical.Left.(type) {
    case hexaParser.LogicalExpression:
        if exp.Operator == logical.Operator {
            m.flatten(exp)
        } else {
            flattened := makeFlattenedLogical(exp)
            m.Expressions = append(m.Expressions, flattened)
        }
    default:
        m.Expressions = append(m.Expressions, exp)
    }

    switch exp := logical.Right.(type) {
    case hexaParser.LogicalExpression:
        if exp.Operator == logical.Operator {
            m.flatten(exp)
        } else {
            flattened := makeFlattenedLogical(exp)
            m.Expressions = append(m.Expressions, flattened)
        }
    default:
        m.Expressions = append(m.Expressions, exp)
    }
}

func checkAndFlatten(expression Expression) Expression {
    switch exp := expression.(type) {
    case hexaParser.LogicalExpression:
        return makeFlattenedLogical(exp)

    default:
        return exp
    }
}

func (mapper *CedarConditionMapper) MapConditionToCedar(condition *conditions.ConditionInfo) (string, error) {
    // assumes https://github.com/google/cel-spec/blob/master/doc/langdef.md#logical-operators
    if condition == nil {
        return "", nil
    }
    ast, err := conditions.ParseConditionRuleAst(*condition)
    if err != nil {
        return "", err
    }
    root := ast

    err = checkCompatibility(root)
    if err != nil {
        return "", err
    }

    isUnless := false
    if condition.Action == conditions.ADeny {
        isUnless = true
    }
    // This logic needs to decide whether to start with multiple when/unless phrases

    // we have a lot of layers of ands/ors need to split into multiple clauses
    switch exp := root.(type) {
    case hexaParser.NotExpression:
        flattened := checkAndFlatten(exp.Expression)
        return mapper.mapFlattenedClause(flattened, !isUnless), nil
    case hexaParser.PrecedenceExpression:
        flattened := checkAndFlatten(exp.Expression)
        return mapper.mapFlattenedClause(flattened, isUnless), nil
    case hexaParser.LogicalExpression:
        flattened := checkAndFlatten(root)
        return mapper.mapFlattenedClause(flattened, isUnless), nil
    default:
        return mapper.mapToConditionClause(exp, isUnless), nil
    }
}

// mapFlattenedClause attempts to break condition into multiple when/unless fragments (implied and)
func (mapper *CedarConditionMapper) mapFlattenedClause(exp Expression, isUnless bool) string {

    switch node := exp.(type) {
    case *MultiLogicalExpression:
        if node.Operator == hexaParser.AND {
            sb := strings.Builder{}
            for i, expression := range node.Expressions {
                if i > 0 {
                    sb.WriteRune('\n')
                }
                clauseLine := mapper.mapFlattenedClause(expression, isUnless)
                sb.WriteString(clauseLine)
            }
            return sb.String()
        }
        // Convert the or clauses in one when/unless
        sb := strings.Builder{}

        if isUnless {
            sb.WriteString("unless { ")
        } else {
            sb.WriteString("when { ")
        }
        for i, expression := range node.Expressions {
            if i > 0 {
                sb.WriteString(" || ")
            }
            switch exp := expression.(type) {
            case *MultiLogicalExpression:
                // this is likely a nested and

                sb.WriteString(" (")
                for j, expAnd := range exp.Expressions {
                    clause := mapper.mapFilterExpression(expAnd.(hexaParser.Expression), true)
                    if j > 0 {
                        sb.WriteString(" && ")
                    }
                    sb.WriteString(clause)
                }
                sb.WriteString(")")

            default:
                clause := mapper.mapFilterExpression(exp.(hexaParser.Expression), true)
                sb.WriteString(clause)
            }
        }
        sb.WriteString(" }")
        return sb.String()

    default:
        return mapper.mapToConditionClause(node.(hexaParser.Expression), isUnless)
    }
}

// mapToConditionClause creates a top-level cedar `when` or `unless` clause
func (mapper *CedarConditionMapper) mapToConditionClause(exp hexaParser.Expression, isUnless bool) string {
    sb := strings.Builder{}

    var clause string
    // This removes redundant top leve precedence or not expression
    switch node := exp.(type) {
    case hexaParser.PrecedenceExpression:
        clause = mapper.mapFilterExpression(node.Expression, false)
    case hexaParser.NotExpression:
        isUnless = !isUnless
        clause = mapper.mapFilterExpression(node.Expression, false)
    default:
        clause = mapper.mapFilterExpression(exp, false)
    }
    if isUnless {
        sb.WriteString("unless { ")
    } else {
        sb.WriteString("when { ")
    }
    sb.WriteString(clause)
    sb.WriteString(" }")
    return sb.String()
}

func (mapper *CedarConditionMapper) mapFilterExpression(node hexaParser.Expression, isChild bool) string {

    switch element := node.(type) {
    case hexaParser.NotExpression:
        return mapper.mapFilterNot(&element, isChild)
    case hexaParser.PrecedenceExpression:
        return mapper.mapFilterPrecedence(&element, true)

    case hexaParser.LogicalExpression:
        return mapper.mapFilterLogical(&element, isChild)

    default:
        attrExpression := node.(hexaParser.AttributeExpression)
        return mapper.mapFilterAttrExpr(&attrExpression)
    }

}

func (mapper *CedarConditionMapper) mapFilterNot(notFilter *hexaParser.NotExpression, _ bool) string {
    subExpression := notFilter.Expression
    var clause string
    switch subFilter := subExpression.(type) {
    case hexaParser.LogicalExpression:
        // For the purpose of a not idqlCondition, the logical expression is not a child
        clause = mapper.mapFilterLogical(&subFilter, false)
    default:
        clause = mapper.mapFilterExpression(subFilter, false)
    }

    return fmt.Sprintf("!( %v )", clause)
}

func (mapper *CedarConditionMapper) mapFilterPrecedence(precedenceExpression *hexaParser.PrecedenceExpression, _ bool) string {
    subExpression := precedenceExpression.Expression
    var clause string
    switch subFilter := subExpression.(type) {
    case hexaParser.LogicalExpression:
        // For the purpose of a not idqlCondition, the logical expression is not a child
        clause = mapper.mapFilterLogical(&subFilter, false)
        clause = "(" + clause + ")"
        break
    default:
        clause = mapper.mapFilterExpression(subFilter, false)
    }
    return fmt.Sprintf("%v", clause)
}

func (mapper *CedarConditionMapper) mapFilterLogical(logicFilter *hexaParser.LogicalExpression, isChild bool) string {
    isDouble := false
    var celLeft, celRight string
    switch subFilter := logicFilter.Left.(type) {
    case hexaParser.LogicalExpression:
        if subFilter.Operator == logicFilter.Operator {
            isDouble = true
        }
    }

    celLeft = mapper.mapFilterExpression(logicFilter.Left, !isDouble)

    celRight = mapper.mapFilterExpression(logicFilter.Right, !isDouble)

    switch logicFilter.Operator {
    default:
        return fmt.Sprintf("%v && %v", celLeft, celRight)
    case hexaParser.OR:
        if isChild {
            // Add precedence to preserve order
            return fmt.Sprintf("(%v || %v)", celLeft, celRight)
        } else {
            return fmt.Sprintf("%v || %v", celLeft, celRight)
        }
    }
}

// removeQuotes checks for quotes and removes them if present
func removeQuotes(val string) string {
    if strings.HasSuffix(val, "\"") && strings.HasPrefix(val, "\"") {
        unquote, err := strconv.Unquote(val)
        if err == nil {
            return unquote
        }
    }
    return val
}

func (mapper *CedarConditionMapper) mapFilterAttrExpr(attrExpr *hexaParser.AttributeExpression) string {
    compareValue := prepareValue(attrExpr)

    mapPath := mapper.NameMapper.GetProviderAttributeName(attrExpr.AttributePath)

    isDecimal := false
    format := "%s %s %s"
    decimalVal, err := types.ParseDecimal(compareValue)
    if err == nil {
        isDecimal = true
        format = "%s.%s(%s)"
    }

    switch attrExpr.Operator {

    case hexaParser.NE:
        return mapPath + " != " + compareValue
    case hexaParser.LT:
        if isDecimal {
            return fmt.Sprintf(format, mapPath, "lessThan", decimalVal.String())
        }
        return fmt.Sprintf(format, mapPath, "<", compareValue)
    case hexaParser.LE:
        if isDecimal {
            return fmt.Sprintf(format, mapPath, "lessThanOrEqual", decimalVal.String())
        }
        return fmt.Sprintf(format, mapPath, "<=", compareValue)
    case hexaParser.GT:
        if isDecimal {
            return fmt.Sprintf(format, mapPath, "greaterThan", decimalVal.String())
        }
        return fmt.Sprintf(format, mapPath, ">", compareValue)
    case hexaParser.GE:
        if isDecimal {
            return fmt.Sprintf(format, mapPath, "greaterThanOrEqual", decimalVal.String())
        }
        return fmt.Sprintf(format, mapPath, ">=", compareValue)
    case hexaParser.SW:
        return fmt.Sprintf("%s like \"%s*\"", mapPath, removeQuotes(compareValue))
    case hexaParser.EW:
        return fmt.Sprintf("%s like \"*%s\"", mapPath, removeQuotes(compareValue))
    case hexaParser.PR:
        lastIndex := strings.LastIndex(mapPath, ".")
        left := mapPath[0:lastIndex]
        right := mapPath[lastIndex+1:]
        return fmt.Sprintf("%s has %s", left, right)
    case hexaParser.CO:
        return mapPath + ".contains(" + compareValue + ")"
    case hexaParser.IN:
        return mapPath + " in " + compareValue
    default:
        return mapPath + " == " + compareValue
    }

}

/*
If the value type is string, it needs to be quoted.
*/
func prepareValue(attrExpr *hexaParser.AttributeExpression) string {
    compValue := attrExpr.CompareValue
    if compValue == "" {
        return ""
    }

    // Check for integer

    if _, err := strconv.ParseInt(compValue, 10, 64); err == nil {
        return compValue
    }

    if _, err := strconv.ParseFloat(compValue, 64); err == nil {
        return compValue
    }

    if compValue == "true" || compValue == "false" {
        return compValue
    }

    // if it has a quote embedded leave it alone
    if strings.Index(compValue, "\"") >= 0 {
        return compValue
    }

    // assume it is a string and return with quotes
    return fmt.Sprintf("\"%s\"", attrExpr.CompareValue)

}

func checkCompatibility(e hexaParser.Expression) error {
    var err error
    switch v := e.(type) {
    case hexaParser.LogicalExpression:
        err = checkCompatibility(v.Left)
        if err != nil {
            return err
        }
        err = checkCompatibility(v.Right)
        if err != nil {
            return err
        }
    case hexaParser.NotExpression:
        return checkCompatibility(v.Expression)
    case hexaParser.PrecedenceExpression:
        return checkCompatibility(v.Expression)
    case hexaParser.ValuePathExpression:
        return errors.New("IDQL ValuePath expression mapping to Google CEL currently not supported")
    case hexaParser.AttributeExpression:
        return nil
    }
    return nil
}
