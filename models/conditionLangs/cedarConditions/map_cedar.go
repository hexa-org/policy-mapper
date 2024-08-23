package cedarConditions

import (
    "errors"
    "fmt"
    "strconv"
    "strings"

    cedarParser "github.com/cedar-policy/cedar-go/x/exp/parser"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
    hexaParser "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions/parser"
    log "golang.org/x/exp/slog"
)

func MapCedarConditionToHexa(cedarConditions []cedarParser.Condition) (*conditions.ConditionInfo, error) {

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
        if cedarConditions[0].Type == cedarParser.ConditionWhen {
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
func mapConditionClause(cond cedarParser.Condition, isSingle bool) (string, error) {
    exp := cond.Expression
    var clause hexaParser.Expression
    var err error
    switch cond.Type {
    case cedarParser.ConditionWhen:
        // if there is only a single condition clause then we don't need precedence brackets - can treat as nested
        clause, err = mapCedarExpression(exp, isSingle)

    case cedarParser.ConditionUnless:
        var notClause hexaParser.Expression
        notClause, err = mapCedarExpression(exp, isSingle)
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

func mapCedarExpression(expression cedarParser.Expression, isNested bool) (hexaParser.Expression, error) {
    switch expression.Type {
    case cedarParser.ExpressionOr:
        expressions := expression.Or.Ands
        if len(expressions) == 1 {
            return mapCedarAnd(expressions[0])
        }
        return mapCedarOrs(expressions, isNested)
    case cedarParser.ExpressionIf:
        return nil, errors.New("hexa cedar mapper does not support if clauses")
    }
    return nil, errors.New(fmt.Sprintf("Unexpected expression type: %v", expression.Type))
}

func mapCedarOrs(ands []cedarParser.And, isNested bool) (hexaParser.Expression, error) {
    lh, err := mapCedarAnd(ands[0])
    if err != nil {
        return nil, err
    }

    if len(ands) == 2 {
        rh, err := mapCedarAnd(ands[1])
        if err != nil {
            return nil, err
        }
        if isNested {
            return makeLogical(hexaParser.OR, lh, rh), nil
        }
        return hexaParser.PrecedenceExpression{
            Expression: makeLogical(hexaParser.OR, lh, rh),
        }, nil
    }

    rh, err := mapCedarOrs(ands[1:], true)
    if err != nil {
        return nil, err
    }
    if isNested {
        return makeLogical(hexaParser.OR, lh, rh), nil
    }
    return hexaParser.PrecedenceExpression{
        Expression: makeLogical(hexaParser.OR, lh, rh),
    }, nil
}

func mapCedarAnd(and cedarParser.And) (hexaParser.Expression, error) {
    relations := and.Relations
    switch len(relations) {
    case 1:
        return mapCedarRelation(relations[0])
    case 2:
        lh, err := mapCedarRelation(relations[0])
        if err != nil {
            return nil, err
        }
        rh, err := mapCedarRelation(relations[1])
        if err != nil {
            return nil, err
        }
        return makeLogical(hexaParser.AND, lh, rh), nil
    default:
        lh, err := mapCedarRelation(relations[0])
        if err != nil {
            return nil, err
        }
        remainAnd := cedarParser.And{
            Relations: relations[1:],
        }
        rh, err := mapCedarAnd(remainAnd)
        if err != nil {
            return nil, err
        }
        return makeLogical(hexaParser.AND, lh, rh), nil
    }
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

func getSubExpression(rel cedarParser.Relation) (*cedarParser.Expression, error) {
    add := rel.Add

    primary, err := getPrimary(add)
    if err != nil {
        return nil, err
    }
    return &primary.Expression, nil
}

func parseRelNone(rel cedarParser.Relation) (hexaParser.Expression, error) {

    unaryExpression, err := getSubExpression(rel)
    if err != nil {
        return nil, err
    }
    primary, _ := getPrimary(rel.Add)
    if primary != nil {
        switch primary.Type {
        case cedarParser.PrimaryRecInits:
            return nil, errors.New("cedar RecInits values not supported")
        case cedarParser.PrimaryVar:
            accesses := rel.Add.Mults[0].Unaries[0].Member.Accesses
            left := primary.Var.String()
            op := hexaParser.CO
            if accesses != nil {
                for _, access := range accesses {
                    switch access.Type {
                    case cedarParser.AccessField:
                        left = left + "." + access.Name
                    case cedarParser.AccessIndex:
                        left = left + "[" + strconv.Quote(access.Name) + "]"
                    case cedarParser.AccessCall:
                        switch access.Name {
                        case "contains":
                            op = hexaParser.CO
                        case "lessThan":
                            op = hexaParser.LT
                        case "greaterThan":
                            op = hexaParser.GT
                        case "lessThanOrEqual":
                            op = hexaParser.LE
                        case "greaterThanOrEqual":
                            op = hexaParser.GE

                        default:
                            return nil, errors.New(fmt.Sprintf("comparison function %s not supported by IDQL at this time", access.Name))
                        }
                        sb := strings.Builder{}
                        for i, e := range access.Expressions {
                            if i > 0 {
                                // return nil, errors.New(fmt.Sprintf("set comparisons not supported: %s", access.String()))
                                sb.WriteString(", ")
                            }
                            sb.WriteString(e.String())
                        }
                        return hexaParser.AttributeExpression{
                            AttributePath: left,
                            Operator:      op,
                            CompareValue:  sb.String(),
                        }, nil

                    }
                }
            }
            return nil, errors.New(fmt.Sprintf("unknown Cedar PrimaryVar relation (%s)", rel.String()))
        default:
            // fall through and treat as precedence brackets
        }
    }

    // This is just a set of brackets (precedence)
    mapExp, err := mapCedarExpression(*unaryExpression, true)
    if err != nil {
        return nil, err
    }
    if mapExp == nil {
        return nil, nil
    }
    return hexaParser.PrecedenceExpression{Expression: mapExp}, nil

}

func getPrimary(add cedarParser.Add) (*cedarParser.Primary, error) {
    mults := add.Mults
    if mults == nil {
        return nil, errors.New("no primary found")
    }
    return &mults[0].Unaries[0].Member.Primary, nil
}

func convertPrimary(add cedarParser.Add) (string, error) {
    prime, _ := getPrimary(add)

    if prime != nil {
        switch prime.Type {
        case cedarParser.PrimaryExpr:
            exp := prime.Expression
            if exp.Type == cedarParser.ExpressionIf {
                return "", errors.New("relation expressions containing if not supported")
            }
        case cedarParser.PrimaryRecInits:
            return "", errors.New("relation expressions containing inits {} not supported")
        case cedarParser.PrimaryVar:
            // This is the case where an index is used to reference sub-attribute principal["name"]
            primeAttr := prime.Var.String()
            accesses := add.Mults[0].Unaries[0].Member.Accesses
            sb := strings.Builder{}
            sb.WriteString(primeAttr)
            for _, access := range accesses {
                sb.WriteRune('.')
                sb.WriteString(access.Name)
            }
            return sb.String(), nil
            // otherwise just fall through and return the unmapped value
        default:
        }

    }
    return add.String(), nil

}

func mapCedarRelation(rel cedarParser.Relation) (hexaParser.Expression, error) {
    switch rel.Type {
    case cedarParser.RelationNone:
        // this is  Precedence ( )
        // exp,err := mapCedarAnd(rel.RelOpRhs)
        return parseRelNone(rel)

    case cedarParser.RelationRelOp:
        var err error

        left, err := convertPrimary(rel.Add)
        if err != nil {
            return nil, err
        }

        op := rel.RelOp

        right, err := convertPrimary(rel.RelOpRhs)
        if err != nil {
            return nil, err
        }
        return hexaParser.AttributeExpression{
            AttributePath: left,
            Operator:      mapCedarOperator(op),
            CompareValue:  right,
        }, nil
    case cedarParser.RelationHasIdent:
        attribute := rel.Add.String() + "." + rel.Str
        return hexaParser.AttributeExpression{
            AttributePath: attribute,
            Operator:      hexaParser.PR,
            CompareValue:  "",
        }, nil
    case cedarParser.RelationHasLiteral:
        // This is the same as HasIdent except that the attribute name has a space in it
        attribute := rel.Add.String() + ".\"" + rel.Str + "\""
        return hexaParser.AttributeExpression{
            AttributePath: attribute,
            Operator:      hexaParser.PR,
            CompareValue:  "",
        }, nil
    case cedarParser.RelationIs:
        // Closest equivalent would be User co principal
        return hexaParser.AttributeExpression{
            AttributePath: rel.Add.String(),
            Operator:      hexaParser.IS,
            CompareValue:  rel.Path.String(),
        }, nil

    case cedarParser.RelationIsIn:
        isExpression := hexaParser.AttributeExpression{
            AttributePath: rel.Add.String(),
            Operator:      hexaParser.IS,
            CompareValue:  rel.Path.String(),
        }
        inExpression := hexaParser.AttributeExpression{
            AttributePath: rel.Add.String(),
            Operator:      hexaParser.IN,
            CompareValue:  rel.Entity.String(),
        }
        return hexaParser.LogicalExpression{
            Operator: hexaParser.AND,
            Left:     isExpression,
            Right:    inExpression,
        }, nil
    }
    return nil, errors.New(fmt.Sprintf("Unknown Relation type: %s, source: %s", rel.Type, rel.String()))
}

func mapCedarOperator(op cedarParser.RelOp) hexaParser.CompareOperator {
    switch op {
    case cedarParser.RelOpEq:
        return hexaParser.EQ
    case cedarParser.RelOpNe:
        return hexaParser.NE
    case cedarParser.RelOpLt:
        return hexaParser.LT
    case cedarParser.RelOpLe:
        return hexaParser.LE
    case cedarParser.RelOpGt:
        return hexaParser.GT
    case cedarParser.RelOpGe:
        return hexaParser.GE
    case cedarParser.RelOpIn:
        return hexaParser.IN
    }
    // Cedar does not appear to have an equivalent of hexaParser.CO
    // this should not happen.
    log.Error(fmt.Sprintf("Unexpected relation operator encountered: %s", op))
    return hexaParser.CompareOperator(op)
}
