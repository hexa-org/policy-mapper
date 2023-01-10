package googleCel

/*
 Condition mapper for Google IAM - See: https://cloud.google.com/iam/docs/conditions-overview
*/
import (
	"errors"
	"fmt"
	celv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/filters/cel/v3"
	"github.com/google/cel-go/cel"
	"policy-conditions/policySupport/filter"
	"strconv"
	"strings"

	"google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"policy-conditions/policySupport/conditions"
)

var (
	env, _ = cel.NewEnv()
)

type GoogleConditionMapper struct {
	NameMapper *conditions.AttributeMap
}

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
	element := *ast
	return mapper.MapFilter(&element, false)

}

func (mapper *GoogleConditionMapper) MapFilter(ast *filter.Expression, isChild bool) (string, error) {

	// dereference
	deref := *ast

	switch element := deref.(type) {
	case filter.NotExpression:
		return mapper.mapFilterNot(&element, isChild)
	case filter.PrecedenceExpression:
		return mapper.mapFilterPrecedence(&element, true)

	case filter.LogicalExpression:
		return mapper.mapFilterLogical(&element, isChild)

	case filter.AttributeExpression:
		return mapper.mapFilterAttrExpr(&element)
	}

	return "", fmt.Errorf("unimplemented IDQL to CEL expression term type(%T): %v", ast, ast)
}

func (mapper *GoogleConditionMapper) mapFilterNot(notFilter *filter.NotExpression, isChild bool) (string, error) {
	subExpression := notFilter.Expression
	var celFilter string
	var err error
	switch subFilter := subExpression.(type) {
	case filter.LogicalExpression:
		// For the purpose of a not filter, the logical expression is not a child
		celFilter, err = mapper.mapFilterLogical(&subFilter, false)
		celFilter = "(" + celFilter + ")"
		break
	default:
		celFilter, err = mapper.MapFilter(&subFilter, false)
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("!%v", celFilter), nil
}

func (mapper *GoogleConditionMapper) mapFilterPrecedence(pfilter *filter.PrecedenceExpression, isChild bool) (string, error) {
	subExpression := pfilter.Expression
	var celFilter string
	var err error
	switch subFilter := subExpression.(type) {
	case filter.LogicalExpression:
		// For the purpose of a not filter, the logical expression is not a child
		celFilter, err = mapper.mapFilterLogical(&subFilter, false)
		celFilter = "(" + celFilter + ")"
		break
	default:
		celFilter, err = mapper.MapFilter(&subFilter, false)
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", celFilter), nil
}

func (mapper *GoogleConditionMapper) mapFilterLogical(logicFilter *filter.LogicalExpression, isChild bool) (string, error) {
	isDouble := false
	var celLeft, celRight string
	var err error
	switch subFilter := logicFilter.Left.(type) {
	case filter.LogicalExpression:
		if subFilter.Operator == logicFilter.Operator {
			isDouble = true
		}
	}

	celLeft, err = mapper.MapFilter(&logicFilter.Left, !isDouble)
	if err != nil {
		return "", err
	}
	celRight, err = mapper.MapFilter(&logicFilter.Right, !isDouble)
	if err != nil {
		return "", err
	}

	switch logicFilter.Operator {
	case filter.AND:
		return fmt.Sprintf("%v && %v", celLeft, celRight), nil
	case filter.OR:
		if isChild {
			// Add precedence to preserve order
			return fmt.Sprintf("(%v || %v)", celLeft, celRight), nil
		} else {
			return fmt.Sprintf("%v || %v", celLeft, celRight), nil
		}
	}
	return "", errors.New("Invalid logic operator detected: " + logicFilter.String())
}

func (mapper *GoogleConditionMapper) mapFilterAttrExpr(attrExpr *filter.AttributeExpression) (string, error) {
	compareValue := prepareValue(attrExpr)

	mapPath := mapper.NameMapper.GetProviderAttributeName(attrExpr.AttributePath)

	switch attrExpr.Operator {
	case filter.EQ:
		return mapPath + " == " + compareValue, nil
	case filter.NE:
		return mapPath + " != " + compareValue, nil
	case filter.LT:
		return mapPath + " < " + compareValue, nil
	case filter.LE:
		return mapPath + " <= " + compareValue, nil
	case filter.GT:
		return mapPath + " > " + compareValue, nil
	case filter.GE:
		return mapPath + " >= " + compareValue, nil
	case filter.SW:
		return mapPath + ".startsWith(" + compareValue + ")", nil
	case filter.EW:
		return mapPath + ".endsWith(" + compareValue + ")", nil
	case filter.PR:
		return "has(" + mapPath + ")", nil
	case filter.CO:
		return mapPath + ".contains(" + compareValue + ")", nil
	case filter.IN:
		return mapPath + " in " + compareValue, nil

	}
	return "", fmt.Errorf("unimplemented or unexpected operand (%s): %s", attrExpr.Operator, attrExpr.String())
}

/*
If the value type is string, it needs to be quoted.
*/
func prepareValue(attrExpr *filter.AttributeExpression) string {
	compValue := attrExpr.CompareValue
	if compValue == "" {
		return ""
	}

	// Check for integer

	if _, err := strconv.ParseInt(compValue, 10, 64); err == nil {
		return compValue
	}

	if compValue == "true" || compValue == "false" {
		return compValue
	}

	// assume it is a string and return with quotes
	return fmt.Sprintf("\"%s\"", attrExpr.CompareValue)

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
		return conditions.ConditionInfo{}, errors.New("CEL Mapping Error: " + issues.String())
	}

	idqlAst, err := mapper.mapCelExpr(celAst.Expr(), false)
	if err != nil {
		return conditions.ConditionInfo{
			Rule: "",
		}, errors.New("IDQL condition mapper error: " + err.Error())
	}

	condString, err := conditions.SerializeExpression(&idqlAst)
	if err != nil {
		return conditions.ConditionInfo{
			Rule: "",
		}, err
	}
	return conditions.ConditionInfo{
		Rule:   condString,
		Action: "allow",
	}, nil
}

func (mapper *GoogleConditionMapper) mapCelExpr(expression *expr.Expr, isChild bool) (filter.Expression, error) {

	cexpr := expression.GetCallExpr()

	if cexpr != nil {
		return mapper.mapCallExpr(cexpr, isChild)
	}

	kind := expression.GetExprKind()
	switch v := kind.(type) {
	case *expr.Expr_SelectExpr:
		return mapper.mapSelectExpr(v)
	}

	return nil, fmt.Errorf("expression of type %T (Google CEL) not implemented/supported in IDQL: %s", cexpr, cexpr.String())
}

func (mapper *GoogleConditionMapper) mapSelectExpr(selection *expr.Expr_SelectExpr) (filter.Expression, error) {
	field := selection.SelectExpr.GetField()
	if !selection.SelectExpr.GetTestOnly() {
		return nil, errors.New("unimplemented Google CEL Select Expression: " + selection.SelectExpr.String())
	}
	ident := selection.SelectExpr.GetOperand().GetIdentExpr()
	if ident == nil {
		return nil, errors.New("unimplemented Google CEL Select Expression: " + selection.SelectExpr.String())
	}
	name := ident.GetName()
	attr := name + "." + field
	path := mapper.NameMapper.GetHexaFilterAttributePath(attr)
	return filter.AttributeExpression{
		AttributePath: path,
		Operator:      filter.PR,
	}, nil
}

func (mapper *GoogleConditionMapper) mapCallExpr(expression *expr.Expr_Call, isChild bool) (filter.Expression, error) {
	operand := expression.GetFunction()
	switch operand {
	case "_&&_":
		return mapper.mapCelLogical(expression.Args, true, isChild)
	case "_||_":
		return mapper.mapCelLogical(expression.Args, false, isChild)
	case "_!_", "!_":
		return mapper.mapCelNot(expression.Args, isChild), nil //was false
	case "_==_":
		return mapper.mapCelAttrCompare(expression.Args, filter.EQ), nil
	case "_!=_":
		return mapper.mapCelAttrCompare(expression.Args, filter.NE), nil
	case "_>_":
		return mapper.mapCelAttrCompare(expression.Args, filter.GT), nil
	case "_<_":
		return mapper.mapCelAttrCompare(expression.Args, filter.LT), nil
	case "_<=_":
		return mapper.mapCelAttrCompare(expression.Args, filter.LE), nil
	case "_>=_":
		return mapper.mapCelAttrCompare(expression.Args, filter.GE), nil
	case "@in":
		return mapper.mapCelAttrCompare(expression.Args, filter.IN), nil
	case "startsWith", "endsWith", "contains", "has":
		return mapper.mapCelAttrFunction(expression)
	}

	return nil, errors.New("Operand: " + operand + " not implemented.")
}

func (mapper *GoogleConditionMapper) mapCelAttrFunction(expression *expr.Expr_Call) (filter.Expression, error) {
	target := expression.GetTarget()
	selection := target.GetSelectExpr()
	operand := selection.GetOperand()
	//subattr := selection.Field
	name := operand.GetIdentExpr().GetName()
	var path string
	if name == "" {
		name = target.GetIdentExpr().GetName()
		path = mapper.NameMapper.GetHexaFilterAttributePath(name)

	} else {
		subattr := selection.GetField()
		path = mapper.NameMapper.GetHexaFilterAttributePath(name + "." + subattr)
	}

	switch expression.GetFunction() {
	case "startsWith":
		rh := expression.GetArgs()[0].GetConstExpr().GetStringValue()
		return filter.AttributeExpression{
			AttributePath: path,
			Operator:      filter.SW,
			CompareValue:  rh,
		}, nil
	case "endsWith":
		rh := expression.GetArgs()[0].GetConstExpr().GetStringValue()
		return filter.AttributeExpression{
			AttributePath: path,
			Operator:      filter.EW,
			CompareValue:  rh,
		}, nil
	case "contains":
		rh := expression.GetArgs()[0].GetConstExpr().GetStringValue()
		return filter.AttributeExpression{
			AttributePath: path,
			Operator:      filter.CO,
			CompareValue:  rh,
		}, nil
	case "has":
		return filter.AttributeExpression{
			AttributePath: path,
			Operator:      filter.PR,
		}, nil
	}
	return nil, errors.New(fmt.Sprintf("Google expression function (%s) not supported in expression: %s", expression.GetFunction(), expression.String()))

}

func (mapper *GoogleConditionMapper) mapCelAttrCompare(expressions []*expr.Expr, operator filter.CompareOperator) filter.Expression {
	//target :=

	path := ""
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
		path = selectExpr.GetOperand().GetIdentExpr().Name + "." + selectExpr.GetField()
	} else {
		path = ident.GetName()
	}

	// map the path name
	path = mapper.NameMapper.GetHexaFilterAttributePath(path)
	constExpr := expressions[1].GetConstExpr().String()

	elems := strings.SplitN(constExpr, ":", 2)
	rh := ""

	if len(elems) == 2 {
		switch elems[0] {
		case "string_value":
			rh = expressions[1].GetConstExpr().GetStringValue()
		default:
			rh = elems[1]
		}
	} else {
		rh = expressions[1].GetConstExpr().GetStringValue()
	}
	attrFilter := filter.AttributeExpression{
		AttributePath: path,
		Operator:      operator,
		CompareValue:  rh,
	}
	if isNot {
		return filter.NotExpression{
			Expression: attrFilter,
		}
	}
	return attrFilter
}

func (mapper *GoogleConditionMapper) mapCelNot(expressions []*expr.Expr, isChild bool) filter.Expression {

	expression, _ := mapper.mapCelExpr(expressions[0], false) // ischild is ignored because of not

	notFilter := filter.NotExpression{
		Expression: expression,
	}
	return notFilter
}

func (mapper *GoogleConditionMapper) mapCelLogical(expressions []*expr.Expr, isAnd bool, isChild bool) (filter.Expression, error) {
	filters := make([]filter.Expression, len(expressions))
	var err error
	// collapse n clauses back into a series of nested pairwise and/or clauses
	for i, v := range expressions {
		filters[i], err = mapper.mapCelExpr(v, true)
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
		subFilter := filter.LogicalExpression{
			Left:     filters[i-2],
			Right:    filters[i-1],
			Operator: filter.LogicalOperator(op),
		}

		filters[i-2] = subFilter
		filters = filters[0 : i-1 : i-1]
	}

	// Surround with precedence to preserve order
	return filters[0], nil
}
