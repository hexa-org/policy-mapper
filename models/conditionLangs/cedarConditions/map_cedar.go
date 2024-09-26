package cedarConditions

import (
    "encoding/json"
    "errors"
    "fmt"
    "strconv"
    "strings"

    "github.com/cedar-policy/cedar-go/types"
    cedarjson "github.com/hexa-org/policy-mapper/models/formats/cedar/json"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
    hexaParser "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions/parser"
)

func MapCedarConditionToHexa(cedarConditions []cedarjson.ConditionJSON) (*conditions.ConditionInfo, error) {

    if cedarConditions == nil {
        return nil, nil
    }

    condInfo := &conditions.ConditionInfo{}

    var err error
    switch len(cedarConditions) {
    case 0:
        return nil, nil
    case 1:
        condInfo.Rule, err = mapConditionClause(cedarConditions[0], true)
        if cedarConditions[0].Kind == "when" {
            condInfo.Action = conditions.AAllow
        } else {
            condInfo.Action = conditions.ADeny
        }
    default:
        merge := ""
        for i, cond := range cedarConditions {
            var clause string
            clause, err = mapConditionClause(cond, false)
            if i == 0 {
                merge = clause
            } else {
                merge = fmt.Sprintf("%s %v %s", merge, hexaParser.AND, clause)
            }
        }
        condInfo.Rule = merge
        condInfo.Action = conditions.AAllow
    }

    return condInfo, err
}

// mapConditionClause maps a when/unless clause
func mapConditionClause(cond cedarjson.ConditionJSON, isSingle bool) (string, error) {
    body := cond.Body
    var clause hexaParser.Expression
    var err error
    switch cond.Kind {
    case "when":
        // if there is only a single condition clause then we don't need precedence brackets - can treat as nested
        clause, err = mapCedarNode(body, !isSingle)

    case "unless":
        var notClause hexaParser.Expression
        notClause, err = mapCedarNode(body, !isSingle)
        if isSingle {
            // The outer when/unless handles it
            clause = notClause
        } else {
            clause = hexaParser.NotExpression{
                Expression: notClause,
            }
        }

    }
    res := ""
    if clause != nil {
        res = clause.String()
    }
    return res, err
}

func sliceToStringArray(vals []string) string {

    return fmt.Sprintf("[%s]", strings.Join(vals, ", "))
}

func mapCedarRelationComparator(node cedarjson.NodeJSON) (string, error) {
    switch {
    case node.Value != nil:
        val := node.Value.V
        switch item := val.(type) {
        case types.String:
            return strconv.Quote(val.String()), nil
        case types.EntityUID:
            return fmt.Sprintf("%s::\"%s\"", item.Type, item.ID), nil
        default:
            return val.String(), nil
        }

    case node.Var != nil:
        return *node.Var, nil

    case node.Set != nil:
        vals := make([]string, len(node.Set))
        for k, n := range node.Set {
            value, err := mapCedarRelationComparator(n)
            if err != nil {
                return "", err
            }
            vals[k] = value
        }
        return sliceToStringArray(vals), nil
    case node.Access != nil:
        lh, err := mapCedarRelationComparator(node.Access.Left)
        if err != nil {
            return "", err
        }
        return fmt.Sprintf("%s.%s", lh, node.Access.Attr), nil
    case node.IfThenElse != nil:
        return "", formatNodeParseError(node, "if-then-else not supported by Hexa IDQL: %s")
    default:
        return "", formatNodeParseError(node, "unknown comparator type: %s")
    }
}

func mapRelation(op hexaParser.CompareOperator, left cedarjson.NodeJSON, right cedarjson.NodeJSON) (hexaParser.Expression, error) {

    lh, err := mapCedarRelationComparator(left)
    if err != nil {
        return nil, err
    }
    rh, err := mapCedarRelationComparator(right)
    if err != nil {
        return nil, err
    }
    return hexaParser.AttributeExpression{
        AttributePath: lh,
        Operator:      op,
        CompareValue:  rh,
    }, nil
}

func mapCedarFunc(op hexaParser.CompareOperator, nodes []cedarjson.NodeJSON) (hexaParser.Expression, error) {
    var left, right string
    for _, node := range nodes {
        if node.Value != nil {
            right = node.Value.V.String()
        } else if node.Access != nil {
            attr, _ := mapCedarRelationComparator(node.Access.Left)
            left = fmt.Sprintf("%s.%s", attr, node.Access.Attr)
        }
    }

    return hexaParser.AttributeExpression{
        AttributePath: left,
        Operator:      op,
        CompareValue:  right,
    }, nil
}

const likeError = "Hexa supports only SW, EW, and CO comparisons: %s"

func mapCedarNode(node cedarjson.NodeJSON, isNested bool) (hexaParser.Expression, error) {

    switch {
    case node.And != nil:
        return mapCedarAnd(*node.And)
    case node.Or != nil:
        orNode := *node.Or
        return mapCedarOr(orNode, isNested)
    case node.Not != nil:
        body := node.Not.Arg
        exp, err := mapCedarNode(body, isNested)
        if err != nil {
            return nil, err
        }
        return hexaParser.NotExpression{Expression: exp}, nil
    case node.Equals != nil:
        return mapRelation(hexaParser.EQ, node.Equals.Left, node.Equals.Right)
    case node.NotEquals != nil:
        return mapRelation(hexaParser.NE, node.NotEquals.Left, node.NotEquals.Right)
    case node.GreaterThan != nil:
        return mapRelation(hexaParser.GT, node.GreaterThan.Left, node.GreaterThan.Right)
    case node.FuncGreaterThan != nil:
        return mapCedarFunc(hexaParser.GT, node.FuncGreaterThan)
    case node.GreaterThanOrEqual != nil:
        return mapRelation(hexaParser.GE, node.GreaterThanOrEqual.Left, node.GreaterThanOrEqual.Right)
    case node.FuncGreaterThanOrEqual != nil:
        return mapCedarFunc(hexaParser.GE, node.FuncGreaterThanOrEqual)
    case node.LessThan != nil:
        return mapRelation(hexaParser.LT, node.LessThan.Left, node.LessThan.Right)
    case node.FuncLessThan != nil:
        return mapCedarFunc(hexaParser.LT, node.FuncLessThan)
    case node.LessThanOrEqual != nil:
        return mapRelation(hexaParser.LE, node.LessThanOrEqual.Left, node.LessThanOrEqual.Right)
    case node.FuncLessThanOrEqual != nil:
        return mapCedarFunc(hexaParser.LE, node.FuncLessThanOrEqual)
    case node.In != nil:
        return mapRelation(hexaParser.IN, node.In.Left, node.In.Right)
    case node.Contains != nil:
        return mapRelation(hexaParser.CO, node.Contains.Left, node.Contains.Right)
    case node.Is != nil:
        lh, err := mapCedarRelationComparator(node.Is.Left)
        if err != nil {
            return nil, err
        }
        isExp := hexaParser.AttributeExpression{
            AttributePath: lh,
            Operator:      hexaParser.IS,
            CompareValue:  node.Is.EntityType}

        if node.Is.In == nil {
            // this is an is expression only
            return isExp, nil
        }
        // This is the Is In case

        rh, err := mapCedarRelationComparator(*node.Is.In)
        inExp := hexaParser.AttributeExpression{
            AttributePath: lh,
            Operator:      hexaParser.IN,
            CompareValue:  rh}

        return hexaParser.LogicalExpression{
            Operator: hexaParser.AND,
            Left:     isExp,
            Right:    inExp,
        }, nil

    case node.Has != nil:
        lh, err := mapCedarRelationComparator(node.Has.Left)
        if err != nil {
            return nil, err
        }
        hasAttr := node.Has.Attr
        if strings.Contains(hasAttr, " ") {
            hasAttr = strconv.Quote(hasAttr)

        }
        return hexaParser.AttributeExpression{
            AttributePath: fmt.Sprintf("%s.%s", lh, hasAttr),
            Operator:      hexaParser.PR,
            CompareValue:  "",
        }, nil

    case node.Like != nil:
        lh, _ := mapCedarRelationComparator(node.Like.Left)

        pattern := removeQuotes(string(node.Like.Pattern.MarshalCedar()))
        if strings.HasPrefix(pattern, "*") {
            if strings.HasSuffix(pattern, "*") {
                // Map "*<match>*" to Contains
                if !strings.Contains(pattern[1:len(pattern)-1], "*") {
                    return hexaParser.AttributeExpression{
                        AttributePath: lh,
                        Operator:      hexaParser.CO,
                        CompareValue:  strconv.Quote(pattern[1 : len(pattern)-1]),
                    }, nil
                }
            }
            if strings.Contains(pattern[1:], "*") {
                // this is a complex pattern
                return nil, errors.New(fmt.Sprintf(likeError, pattern))
            }
            return hexaParser.AttributeExpression{
                AttributePath: lh,
                Operator:      hexaParser.EW,
                CompareValue:  strconv.Quote(pattern[1:]),
            }, nil
        }
        if strings.HasSuffix(pattern, "*") {

            if strings.Contains(pattern[0:len(pattern)-1], "*") {
                // this is a complex pattern

                return nil, errors.New(fmt.Sprintf(likeError, pattern))
            }
            return hexaParser.AttributeExpression{
                AttributePath: lh,
                Operator:      hexaParser.SW,
                CompareValue:  strconv.Quote(pattern[0 : len(pattern)-1]),
            }, nil
        }
        return nil, errors.New(fmt.Sprintf(likeError, pattern))
    case node.IfThenElse != nil:
        return nil, formatNodeParseError(node, "if-then-else is not supported by Hexa IDQL: %s")

    case node.Negate != nil, node.Subtract != nil, node.Add != nil, node.Multiply != nil:
        return nil, formatNodeParseError(node, "calculations (negate, add, multiply, subtract) are not supported by Hexa IDQL: %s")

    default:
        return nil, formatNodeParseError(node, "unsupported expression: %s")
    }

}

func formatNodeParseError(node cedarjson.NodeJSON, errMessageFmt string) error {
    exp, _ := json.Marshal(node)
    return errors.New(fmt.Sprintf(errMessageFmt, string(exp)))
}

func mapCedarOr(or cedarjson.BinaryJSON, isNested bool) (hexaParser.Expression, error) {
    lh, err := mapCedarNode(or.Left, isNested)
    if err != nil {
        return nil, err
    }

    rh, err := mapCedarNode(or.Right, isNested)
    if err != nil {
        return nil, err
    }
    if !isNested {
        return makeLogical(hexaParser.OR, lh, rh), nil
    }
    return hexaParser.PrecedenceExpression{
        Expression: makeLogical(hexaParser.OR, lh, rh),
    }, nil
}

func mapCedarAnd(and cedarjson.BinaryJSON) (hexaParser.Expression, error) {
    lh, err := mapCedarNode(and.Left, true)
    if err != nil {
        return nil, err
    }

    rh, err := mapCedarNode(and.Right, true)
    if err != nil {
        return nil, err
    }
    return makeLogical(hexaParser.AND, lh, rh), nil

}

// makeLogical checks for null expressions and either simplifies or returns a logical expression
func makeLogical(andor hexaParser.LogicalOperator, lh hexaParser.Expression, rh hexaParser.Expression) hexaParser.Expression {
    if lh == nil {
        return rh
    }
    if rh == nil {
        return lh
    }
    return hexaParser.LogicalExpression{
        Operator: andor,
        Left:     lh,
        Right:    rh,
    }
}
