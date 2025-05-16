package gcpcel

/*
 Condition mapTool for Google IAM - See: https://cloud.google.com/iam/docs/conditions-overview
*/
import (
	"errors"
	"fmt"
	"strconv"

	"github.com/google/cel-go/cel"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions/parser"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/types"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	env, _ = cel.NewEnv()
)

type GoogleConditionMapper struct {
	NameMapper *conditions.AttributeMap
}

func (mapper *GoogleConditionMapper) MapConditionToProvider(condition conditions.ConditionInfo) (string, error) {
	// assumes https://github.com/google/cel-spec/blob/master/doc/langdef.md#logical-operators
	ast, err := conditions.ParseConditionRuleAst(condition)
	if err != nil {
		return "", err
	}
	return mapper.MapFilter(ast)

}

func (mapper *GoogleConditionMapper) MapFilter(ast parser.Expression) (string, error) {
	err := checkCompatibility(ast)
	if err != nil {
		return "", err
	}
	return mapper.mapFilterInternal(ast, false), nil
}

func (mapper *GoogleConditionMapper) mapFilterInternal(ast parser.Expression, isChild bool) string {

	switch element := ast.(type) {
	case parser.NotExpression:
		return mapper.mapFilterNot(element, isChild)
	case parser.PrecedenceExpression:
		return mapper.mapFilterPrecedence(element, true)

	case parser.LogicalExpression:
		return mapper.mapFilterLogical(element, isChild)

	default:
		attrExpression := ast.(parser.AttributeExpression)
		return mapper.mapFilterAttrExpr(attrExpression)
	}
	// return mapTool.mapFilterValuePath(deref.(idqlCondition.ValuePathExpression))
}

func (mapper *GoogleConditionMapper) mapFilterNot(notFilter parser.NotExpression, _ bool) string {
	subExpression := notFilter.Expression
	var celFilter string
	switch subFilter := subExpression.(type) {
	case parser.LogicalExpression:
		// For the purpose of a not idqlCondition, the logical expression is not a child
		celFilter = mapper.mapFilterLogical(subFilter, false)
		celFilter = "(" + celFilter + ")"
		break
	default:
		celFilter = mapper.mapFilterInternal(subFilter, false)
	}

	return fmt.Sprintf("!%v", celFilter)
}

func (mapper *GoogleConditionMapper) mapFilterPrecedence(pfilter parser.PrecedenceExpression, _ bool) string {
	subExpression := pfilter.Expression
	var celFilter string
	switch subFilter := subExpression.(type) {
	case parser.LogicalExpression:
		// For the purpose of a not idqlCondition, the logical expression is not a child
		celFilter = mapper.mapFilterLogical(subFilter, false)
		celFilter = "(" + celFilter + ")"
		break
	default:
		celFilter = mapper.mapFilterInternal(subFilter, false)
	}
	return fmt.Sprintf("%v", celFilter)
}

func (mapper *GoogleConditionMapper) mapFilterLogical(logicFilter parser.LogicalExpression, isChild bool) string {
	isDouble := false
	var celLeft, celRight string
	switch subFilter := logicFilter.Left.(type) {
	case parser.LogicalExpression:
		if subFilter.Operator == logicFilter.Operator {
			isDouble = true
		}
	}

	celLeft = mapper.mapFilterInternal(logicFilter.Left, !isDouble)

	celRight = mapper.mapFilterInternal(logicFilter.Right, !isDouble)

	switch logicFilter.Operator {
	default:
		return fmt.Sprintf("%v && %v", celLeft, celRight)
	case parser.OR:
		if isChild {
			// Add precedence to preserve order
			return fmt.Sprintf("(%v || %v)", celLeft, celRight)
		} else {
			return fmt.Sprintf("%v || %v", celLeft, celRight)
		}
	}
}

func (mapper *GoogleConditionMapper) mapFilterAttrExpr(attrExpr parser.AttributeExpression) string {
	compareValue := ""
	if attrExpr.CompareValue != nil {
		switch attrExpr.CompareValue.(type) {
		case types.Date:
			// GCP dates need to be quoted
			compareValue = fmt.Sprintf("timestamp('%s')", attrExpr.CompareValue.String())
		default:
			compareValue = attrExpr.CompareValue.String()
		}
	}

	mapPath := mapper.NameMapper.GetProviderAttributeName(attrExpr.AttributePath.String())

	switch attrExpr.Operator {

	case parser.NE:
		return mapPath + " != " + compareValue
	case parser.LT:
		return mapPath + " < " + compareValue
	case parser.LE:
		return mapPath + " <= " + compareValue
	case parser.GT:
		return mapPath + " > " + compareValue
	case parser.GE:
		return mapPath + " >= " + compareValue
	case parser.SW:
		return mapPath + ".startsWith(" + compareValue + ")"
	case parser.EW:
		return mapPath + ".endsWith(" + compareValue + ")"
	case parser.PR:
		return "has(" + mapPath + ")"
	case parser.CO:
		return mapPath + ".contains(" + compareValue + ")"
	case parser.IN:
		return mapPath + " in " + compareValue
	default:
		return mapPath + " == " + compareValue
	}

}

func (mapper *GoogleConditionMapper) MapProviderToCondition(expression string) (conditions.ConditionInfo, error) {

	celAst, issues := env.Parse(expression)
	if issues != nil {
		return conditions.ConditionInfo{}, errors.New("CEL Mapping Error: " + issues.String())
	}
	parsedAst, err := cel.AstToParsedExpr(celAst)
	if err != nil {
		return conditions.ConditionInfo{
			Rule: "",
		}, errors.New("IDQL condition mapTool error: " + err.Error())
	}
	idqlAst, err := mapper.mapCelExpr(parsedAst.GetExpr(), false)
	if err != nil {
		return conditions.ConditionInfo{
			Rule: "",
		}, errors.New("IDQL condition mapTool error: " + err.Error())
	}

	condString := conditions.SerializeExpression(idqlAst)

	return conditions.ConditionInfo{
		Rule:   condString,
		Action: "allow",
	}, nil
}

func (mapper *GoogleConditionMapper) mapCelExpr(expression *expr.Expr, isChild bool) (parser.Expression, error) {

	cexpr := expression.GetCallExpr()

	if cexpr != nil {
		return mapper.mapCallExpr(cexpr, isChild)
	}

	kind := expression.GetExprKind()
	switch v := kind.(type) {
	case *expr.Expr_SelectExpr:
		return mapper.mapSelectExpr(v)
	// case *expr.Expr_ComprehensionExpr:
	//	return nil, errors.New("unimplemented CEL 'comprehension expression' not implemented. ")
	default:
		return nil, fmt.Errorf("unimplemented CEL expression: %s", expression.String())
	}
}

func (mapper *GoogleConditionMapper) mapSelectExpr(selection *expr.Expr_SelectExpr) (parser.Expression, error) {
	field := selection.SelectExpr.GetField()
	/*
		if !selection.SelectExpr.GetTestOnly() {
			return nil, errors.New("unimplemented Google CEL Select Expression: " + selection.SelectExpr.String())
		}
	*/

	ident := selection.SelectExpr.GetOperand().GetIdentExpr()

	name := ident.GetName()
	attr := name + "." + field
	path := mapper.NameMapper.GetHexaFilterAttributePath(attr)
	lhv, err := types.ParseValue(path)
	if err != nil {
		return nil, err
	}
	return parser.AttributeExpression{
		AttributePath: lhv,
		Operator:      parser.PR,
	}, nil
}

func (mapper *GoogleConditionMapper) mapCallExpr(expression *expr.Expr_Call, isChild bool) (parser.Expression, error) {
	operand := expression.GetFunction()
	switch operand {
	case "_&&_":
		return mapper.mapCelLogical(expression.Args, true, isChild)
	case "_||_":
		return mapper.mapCelLogical(expression.Args, false, isChild)
	case "_!_", "!_":
		return mapper.mapCelNot(expression.Args, isChild), nil // was false
	case "_==_":
		return mapper.mapCelAttrCompare(expression.Args, parser.EQ)
	case "_!=_":
		return mapper.mapCelAttrCompare(expression.Args, parser.NE)
	case "_>_":
		return mapper.mapCelAttrCompare(expression.Args, parser.GT)
	case "_<_":
		return mapper.mapCelAttrCompare(expression.Args, parser.LT)
	case "_<=_":
		return mapper.mapCelAttrCompare(expression.Args, parser.LE)
	case "_>=_":
		return mapper.mapCelAttrCompare(expression.Args, parser.GE)
	case "@in":
		return mapper.mapCelAttrCompare(expression.Args, parser.IN)

	case "startsWith", "endsWith", "contains", "has":
		return mapper.mapCelAttrFunction(expression)

	}

	return nil, errors.New("unimplemented CEL expression operand: " + operand)
}

func (mapper *GoogleConditionMapper) mapCelAttrFunction(expression *expr.Expr_Call) (parser.Expression, error) {
	target := expression.GetTarget()
	selection := target.GetSelectExpr()
	operand := selection.GetOperand()
	// subattr := selection.Field
	name := operand.GetIdentExpr().GetName()
	var path string
	if name == "" {
		name = target.GetIdentExpr().GetName()
		path = mapper.NameMapper.GetHexaFilterAttributePath(name)

	} else {
		subattr := selection.GetField()
		path = mapper.NameMapper.GetHexaFilterAttributePath(name + "." + subattr)
	}

	lhv, err := types.ParseValue(path)
	if err != nil {
		return nil, err
	}

	rh := strconv.Quote(expression.GetArgs()[0].GetConstExpr().GetStringValue())
	rhv, err := types.ParseValue(rh)
	if err != nil {
		return nil, err
	}
	switch expression.GetFunction() {
	case "startsWith":
		return parser.AttributeExpression{
			AttributePath: lhv,
			Operator:      parser.SW,
			CompareValue:  rhv,
		}, nil
	case "endsWith":
		return parser.AttributeExpression{
			AttributePath: lhv,
			Operator:      parser.EW,
			CompareValue:  rhv,
		}, nil
	case "contains":
		return parser.AttributeExpression{
			AttributePath: lhv,
			Operator:      parser.CO,
			CompareValue:  rhv,
		}, nil
	}
	return nil, errors.New(fmt.Sprintf("unimplemented CEL function:%s", expression.GetFunction()))

}

func convertConstExpr(cexpr *expr.Expr_ConstExpr) (types.Value, error) {
	var rhv types.Value
	var constExpr string
	var err error
	switch constVal := cexpr.ConstExpr.GetConstantKind().(type) {
	case *expr.Constant_StringValue:
		constExpr = constVal.StringValue
		// For some reason, GCP passing time as a string value, try date first
		rhv, err = types.NewDate(constExpr)
		if err != nil {
			rhv = types.NewString(constExpr)
		}
	case *expr.Constant_BoolValue:
		rhv = types.NewBoolean(strconv.FormatBool(constVal.BoolValue))
	case *expr.Constant_Int64Value:
		rhv, err = types.NewNumeric(strconv.FormatInt(constVal.Int64Value, 10))
		if err != nil {
			return nil, err
		}
	case *expr.Constant_DoubleValue:
		rhv, err = types.NewNumeric(fmt.Sprintf("%v", constVal.DoubleValue))
		if err != nil {
			return nil, err
		}
	default:
		rhv, err = types.ParseValue(cexpr.ConstExpr.GetStringValue())
		if err != nil {
			return nil, err
		}
	}
	return rhv, nil
}

func (mapper *GoogleConditionMapper) mapCelAttrCompare(expressions []*expr.Expr, operator parser.CompareOperator) (parser.Expression, error) {
	// target :=

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
			msg := fmt.Sprintf("unimplemented CEL function: %s", callExpr.GetFunction())
			return nil, errors.New(msg)
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

	// Map the RH expression
	kind := expressions[1].GetExprKind()
	var rhv types.Value
	var err error
	switch val := kind.(type) {
	case *expr.Expr_ConstExpr:
		rhv, err = convertConstExpr(val)
		if err != nil {
			return nil, err
		}

	case *expr.Expr_IdentExpr:
		rhv = types.ParseEntity(val.IdentExpr.Name)
	case *expr.Expr_CallExpr:
		callFunc := val.CallExpr.GetFunction()
		args := val.CallExpr.GetArgs()
		switch callFunc {
		case "timestamp":
			val := args[0].GetConstExpr().GetStringValue()
			rhv, err = types.NewDate(val)
			if err != nil {
				return nil, err
			}
		default:
			msg := fmt.Sprintf("unsupported function %s in %s", callFunc, expressions[1].String())
			// fmt.Println("Warning: "+msg)
			return nil, errors.New(msg)
		}
	}

	lhv, err := types.ParseValue(path)
	if err != nil {
		return nil, err
	}

	attrFilter := parser.AttributeExpression{
		AttributePath: lhv,
		Operator:      operator,
		CompareValue:  rhv,
	}
	if isNot {
		return parser.NotExpression{
			Expression: attrFilter,
		}, nil
	}
	return attrFilter, nil
}

func (mapper *GoogleConditionMapper) mapCelNot(expressions []*expr.Expr, _ bool) parser.Expression {

	expression, _ := mapper.mapCelExpr(expressions[0], false) // ischild is ignored because of not

	notFilter := parser.NotExpression{
		Expression: expression,
	}
	return notFilter
}

func (mapper *GoogleConditionMapper) mapCelLogical(expressions []*expr.Expr, isAnd bool, _ bool) (parser.Expression, error) {
	filters := make([]parser.Expression, len(expressions))
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

	// Collapse all the way down to 1 idqlCondition
	for len(filters) > 1 {
		i := len(filters)
		subFilter := parser.LogicalExpression{
			Left:     filters[i-2],
			Right:    filters[i-1],
			Operator: parser.LogicalOperator(op),
		}

		filters[i-2] = subFilter
		filters = filters[0 : i-1 : i-1]
	}

	// Surround with precedence to preserve order
	return filters[0], nil
}

func checkCompatibility(e parser.Expression) error {
	var err error
	switch v := e.(type) {
	case parser.LogicalExpression:
		err = checkCompatibility(v.Left)
		if err != nil {
			return err
		}
		err = checkCompatibility(v.Right)
		if err != nil {
			return err
		}
	case parser.NotExpression:
		return checkCompatibility(v.Expression)
	case parser.PrecedenceExpression:
		return checkCompatibility(v.Expression)
	case parser.ValuePathExpression:
		return errors.New("IDQL ValuePath expression mapping to Google CEL currently not supported")
	case parser.AttributeExpression:
		return nil
	}
	return nil
}
