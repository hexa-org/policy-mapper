package googlecloud

/*
 Condition mapper for Google IAM - See: https://cloud.google.com/iam/docs/conditions-overview
*/
import (
	"errors"
	"fmt"
	celv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	"github.com/google/cel-go/cel"
	"github.com/hexa-org/scim-filter-parser/v2"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	conditions "policy-conditions/policySupport/conditions"
)

var (
	env, _ = cel.NewEnv()
)

type GoogleConditionMapper struct{}

type CelConditionType struct {
	Title       string
	Description string
	Expression  celv3.ExpressionFilter
}

type GcpConditionType struct {
	Title       string
	Description string
	Expression  string
}

func (mapper *GoogleConditionMapper) MapConditionToProvider(condition conditions.ConditionInfo) (string, error) {
	// assumes https://github.com/google/cel-spec/blob/master/doc/langdef.md#logical-operators
	ast, err := conditions.ParseConditionRuleAst(condition)
	if err != nil {
		return "", err
	}

	return MapFilter(ast)

}

func MapFilter(ast interface{}) (string, error) {

	switch ast.(type) {
	case *filter.NotExpression:
		return mapFilterNot(ast.(*filter.NotExpression))

	case *filter.LogicalExpression:
		return mapFilterLogical(ast.(*filter.LogicalExpression))

	case *filter.AttributeExpression:
		return mapFilterAttrExpr(ast.(*filter.AttributeExpression))

	case *filter.PrecedenceExpression:
		return mapPrecedence(ast.(*filter.PrecedenceExpression))
	}

	return "", fmt.Errorf("Unimplemented IDQL expression term type(%T): %v", ast, ast)
}

func mapPrecedence(predFilter *filter.PrecedenceExpression) (string, error) {
	subExpression := predFilter.Expression
	celFilter, err := MapFilter(subExpression)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("(%v)", celFilter), nil
}

func mapFilterNot(notFilter *filter.NotExpression) (string, error) {
	subExpression := notFilter.Expression
	var celFilter string
	var err error
	switch subExpression.(type) {
	case *filter.LogicalExpression:
		celFilter, err = mapFilterLogical(subExpression.(*filter.LogicalExpression))
		celFilter = "(" + celFilter + ")"
		break
	default:
		celFilter, err = MapFilter(subExpression)
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("!%v", celFilter), nil
}

func mapFilterLogical(logicFilter *filter.LogicalExpression) (string, error) {
	celLeft, err := MapFilter(logicFilter.Left)
	if err != nil {
		return "", err
	}
	celRight, err := MapFilter(logicFilter.Right)

	switch logicFilter.Operator {
	case filter.AND:
		return fmt.Sprintf("%v && %v", celLeft, celRight), nil
	case filter.OR:
		return fmt.Sprintf("%v || %v", celLeft, celRight), nil
	}
	return "", errors.New("Invalid logic operator detected: " + logicFilter.String())
}

func mapFilterAttrExpr(attrExpr *filter.AttributeExpression) (string, error) {
	compareValue := prepareValue(attrExpr)

	switch attrExpr.Operator {
	case filter.EQ:
		return attrExpr.AttributePath.String() + " == " + compareValue, nil
	case filter.NE:
		return attrExpr.AttributePath.String() + " != " + compareValue, nil
	case filter.LT:
		return attrExpr.AttributePath.String() + " < " + compareValue, nil
	case filter.LE:
		return attrExpr.AttributePath.String() + " <= " + compareValue, nil
	case filter.GT:
		return attrExpr.AttributePath.String() + " > " + compareValue, nil
	case filter.GE:
		return attrExpr.AttributePath.String() + " >= " + compareValue, nil
	case filter.SW:
		return attrExpr.AttributePath.String() + ".startsWith(" + compareValue + ")", nil
	case filter.EW:
		return attrExpr.AttributePath.String() + ".endsWith(" + compareValue + ")", nil
	case filter.PR:
		return "has(" + attrExpr.AttributePath.String() + ")", nil
	case filter.CO:
		return attrExpr.AttributePath.String() + ".contains(" + compareValue + ")", nil

	}
	return "", fmt.Errorf("unimplemented or unexpected operand (%s): %s", attrExpr.Operator, attrExpr.String())
}

/*
If the value type is string, it needs to be quoted.
*/
func prepareValue(attrExpr *filter.AttributeExpression) string {
	if attrExpr.CompareValue == nil {
		return ""
	}
	switch attrExpr.CompareValue.(type) {
	case string:
		return "\"" + attrExpr.CompareValue.(string) + "\""
	}
	return fmt.Sprint(attrExpr.CompareValue)
}

func (mapper *GoogleConditionMapper) GetAst(expression string) (string, error) {
	ast, issues := env.Parse(expression)
	if issues != nil {
		return "", errors.New(issues.String())
	}
	return ast.Expr().String(), nil

}

func (mapper *GoogleConditionMapper) MapProviderToCondition(expression string) (conditions.ConditionInfo, error) {

	celAst, issues := env.Parse(expression)
	if issues != nil {
		return conditions.ConditionInfo{}, errors.New(issues.String())
	}

	idqlAst, err := mapCelExpr(celAst.Expr(), false)
	if err != nil {
		return conditions.ConditionInfo{
			Rule: "",
		}, err
	}
	return conditions.ConditionInfo{
		Rule:   fmt.Sprint(idqlAst),
		Action: "allow",
	}, nil
}

func mapCelExpr(expression *expr.Expr, isChild bool) (filter.Expression, error) {

	cexpr := expression.GetCallExpr()

	if cexpr != nil {
		return mapCallExpr(cexpr, isChild)
	}

	return nil, fmt.Errorf("expression of type %T (Google CEL) not implemented/supported in IDQL: %s", cexpr, cexpr.String())
}

func mapCallExpr(expression *expr.Expr_Call, isChild bool) (filter.Expression, error) {
	operand := expression.GetFunction()
	switch operand {
	case "_&&_":
		return mapCelLogical(expression.Args, true, isChild)
	case "_||_":
		return mapCelLogical(expression.Args, false, isChild)
	case "_!_", "!_":
		return mapCelNot(expression.Args, isChild), nil
	case "_==_":
		return mapCelAttrCompare(expression.Args, filter.EQ), nil
	case "_!=_":
		return mapCelAttrCompare(expression.Args, filter.NE), nil
	case "_>_":
		return mapCelAttrCompare(expression.Args, filter.GT), nil
	case "_<_":
		return mapCelAttrCompare(expression.Args, filter.LT), nil
	case "_<=_":
		return mapCelAttrCompare(expression.Args, filter.LE), nil
	case "_>=_":
		return mapCelAttrCompare(expression.Args, filter.GE), nil
	case "startsWith", "endsWith", "contains", "has":
		return mapCelAttrFunction(expression)
	}

	return nil, errors.New("Operand: " + operand + " not implemented.")
}

func mapCelAttrFunction(expression *expr.Expr_Call) (filter.Expression, error) {
	target := expression.GetTarget()
	selection := target.GetSelectExpr()
	operand := selection.GetOperand()
	//subattr := selection.Field
	name := operand.GetIdentExpr().GetName()
	var path filter.AttributePath
	if name == "" {
		name = target.GetIdentExpr().GetName()
		path = filter.AttributePath{
			URIPrefix:     nil,
			AttributeName: name,
			SubAttribute:  nil,
		}
	} else {
		subattr := selection.GetField()
		path = filter.AttributePath{
			URIPrefix:     nil,
			AttributeName: name,
			SubAttribute:  &subattr,
		}
	}

	switch expression.GetFunction() {
	case "startsWith":
		rh := expression.GetArgs()[0].GetConstExpr().GetStringValue()
		return &filter.AttributeExpression{
			AttributePath: path,
			Operator:      filter.SW,
			CompareValue:  rh,
		}, nil
	case "endsWith":
		rh := expression.GetArgs()[0].GetConstExpr().GetStringValue()
		return &filter.AttributeExpression{
			AttributePath: path,
			Operator:      filter.EW,
			CompareValue:  rh,
		}, nil
	case "contains":
		rh := expression.GetArgs()[0].GetConstExpr().GetStringValue()
		return &filter.AttributeExpression{
			AttributePath: path,
			Operator:      filter.CO,
			CompareValue:  rh,
		}, nil
	case "has":
		return &filter.AttributeExpression{
			AttributePath: path,
			Operator:      filter.PR,
		}, nil
	}
	return nil, errors.New(fmt.Sprintf("Google expression function (%s) not supported in expression: %s", expression.GetFunction(), expression.String()))

}

func mapCelAttrCompare(expressions []*expr.Expr, operator filter.CompareOperator) filter.Expression {
	//target :=

	path := filter.AttributePath{}
	isNot := false
	callExpr := expressions[0].GetCallExpr()
	lhExpression := expressions[0]
	if callExpr != nil {
		switch callExpr.GetFunction() {
		case "!_":
			isNot = true
			break
		default:
			fmt.Printf("Unexpected CEL function(%s): %s", callExpr.GetFunction(), callExpr.String())
		}
		lhExpression = callExpr.Args[0]
	}
	ident := lhExpression.GetIdentExpr()
	if ident == nil {
		selectExpr := lhExpression.GetSelectExpr()
		path.AttributeName = selectExpr.GetOperand().GetIdentExpr().Name
		subAttr := selectExpr.GetField()
		path.SubAttribute = &subAttr
	} else {
		path.AttributeName = ident.GetName()
	}
	rh := expressions[1].GetConstExpr().GetStringValue()
	attrFilter := &filter.AttributeExpression{
		AttributePath: path,
		Operator:      operator,
		CompareValue:  rh,
	}
	if isNot {
		return &filter.NotExpression{
			Expression: attrFilter,
		}
	}
	return attrFilter
}

func mapCelNot(expressions []*expr.Expr, isChild bool) filter.Expression {
	expression, _ := mapCelExpr(expressions[0], false) // ischild is ignored because of not
	notFilter := &filter.NotExpression{
		Expression: expression,
	}
	return notFilter
}

func mapCelLogical(expressions []*expr.Expr, isAnd bool, isChild bool) (filter.Expression, error) {
	filters := make([]filter.Expression, len(expressions))
	var err error
	// collapse n clauses back into a series of nested pairwise and/or clauses
	for i, v := range expressions {
		filters[i], err = mapCelExpr(v, true)
		if err != nil {
			return nil, err
		}
	}
	var op string
	if isAnd {
		op = "and"
	} else {
		op = "or"

	}

	//Collapse all the way down to 1 filter
	for len(filters) > 1 {
		i := len(filters)
		subFilter := &filter.LogicalExpression{
			Left:     filters[i-2],
			Right:    filters[i-1],
			Operator: filter.LogicalOperator(op),
		}

		filters[i-2] = subFilter
		filters = filters[0 : i-1 : i-1]
	}
	if isAnd || !isChild {
		return filters[0], nil
	}

	// Surround with precedence to preserve order
	return &filter.PrecedenceExpression{Expression: filters[0]}, nil
}
