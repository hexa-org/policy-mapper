package conditions

import (
    "fmt"
    "sort"

    "strings"

    conditionparser "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions/parser"
)

const (
    AAllow string = "allow"
    ADeny  string = "deny"
    AAudit string = "audit"
)

type ConditionInfo struct {
    Rule   string `json:"Rule,omitempty" validate:"required"` // in RFC7644 idqlCondition form
    Action string `json:"Action,omitempty"`                   // allow/deny/audit default is allow
}

// Equals performs an AST level compare to test filters are equivalent. NOTE: does not test equivalent attribute expressions at this time
// e.g. level < 5 vs. not(level >= 5) will return as unequal though logically equal.  So while a true is always correct, some equivalent expressions will report false
func (c *ConditionInfo) Equals(compare *ConditionInfo) bool {
    // first just do a simple compare
    if compare == nil {
        return false
    }

    if c.Action != compare.Action {
        return false
    }
    if c.Rule == compare.Rule {
        return true
    }

    // try re-parsing to get consistent spacing etc.
    expression, err := conditionparser.ParseFilter(c.Rule)
    compareExpression, err2 := conditionparser.ParseFilter(compare.Rule)
    if err != nil || err2 != nil {
        return false
    }

    ch1 := make(chan string)
    ch2 := make(chan string)
    var seq1 []string
    var seq2 []string
    go compareWalk(expression, ch1)
    go compareWalk(compareExpression, ch2)

    for item := range ch1 {
        seq1 = append(seq1, item)
    }
    for item := range ch2 {
        seq2 = append(seq2, item)
    }
    sort.Strings(seq1)
    sort.Strings(seq2)

    return slicesAreEqual(seq1, seq2)
    /*
       exp1 := SerializeExpression(expression)
       exp2 := SerializeExpression(compareExpression)

       return exp1 == exp2

    */
}

func slicesAreEqual(a, b []string) bool {
    if len(a) != len(b) {
        return false
    }
    for i, v := range a {
        if !strings.EqualFold(v, b[i]) {
            return false
        }
    }
    return true
}

type AttributeMap struct {
    forward map[string]string
    reverse map[string]string
}

type NameMapper interface {
    // GetProviderAttributeName returns a simple string representation of the mapped attribute name (usually in name[.sub-attribute] form).
    GetProviderAttributeName(hexaName string) string

    // GetHexaFilterAttributePath returns a filterAttributePath which is used to build a SCIM Filter AST
    GetHexaFilterAttributePath(provName string) string
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

// NewNameMapper is called by a condition mapTool provider to instantiate an attribute name translator using interface NameMapper
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

func (n *AttributeMap) GetHexaFilterAttributePath(provName string) string {
    val, exists := n.reverse[provName]
    if !exists {
        val = provName
    }
    return val
}

// ParseConditionRuleAst is used by mapping providers to get the IDQL condition rule AST tree
func ParseConditionRuleAst(condition ConditionInfo) (conditionparser.Expression, error) {
    return conditionparser.ParseFilter(condition.Rule)
}

func ParseExpressionAst(expression string) (conditionparser.Expression, error) {
    return conditionparser.ParseFilter(expression)
}

// SerializeExpression walks the AST and emits the condition in string form. It preserves precedence over the normal idqlCondition.String() method
func SerializeExpression(ast conditionparser.Expression) string {
    return walk(ast, false)
}

func checkNestedLogic(e conditionparser.Expression, op conditionparser.LogicalOperator) string {
    // if the child is a repeat of the parent eliminate brackets (e.g. a or b or c)

    switch v := e.(type) {
    case conditionparser.PrecedenceExpression:
        e = v.Expression
    }

    switch v := e.(type) {
    case conditionparser.LogicalExpression:
        if v.Operator == op {
            return walk(e, false)
        } else {
            return walk(e, true)
        }

    default:
        return walk(e, true)
    }
}

func compareWalk(e conditionparser.Expression, ch chan string) {
    defer close(ch)
    if e != nil {
        compareWalkRecursively(e, ch)
    }
}

func compareWalkRecursively(e conditionparser.Expression, ch chan string) {
    if e != nil {
        val := e.Dif()
        if val != "" {
            ch <- val
        }
        switch exp := e.(type) {
        case conditionparser.PrecedenceExpression:
            compareWalkRecursively(exp.Expression, ch)
        case conditionparser.LogicalExpression:
            compareWalkRecursively(exp.Left, ch)
            compareWalkRecursively(exp.Right, ch)
        case conditionparser.NotExpression:
            compareWalkRecursively(exp.Expression, ch)
        default: // conditionparser.AttributeExpression etc.

        }
    }
    return
}

func walk(e conditionparser.Expression, isChild bool) string {
    switch v := e.(type) {
    case conditionparser.LogicalExpression:
        lhVal := checkNestedLogic(v.Left, v.Operator)

        rhVal := checkNestedLogic(v.Right, v.Operator)

        if isChild && v.Operator == conditionparser.OR {
            return fmt.Sprintf("(%v or %v)", lhVal, rhVal)
        } else {
            return fmt.Sprintf("%v %v %v", lhVal, v.Operator, rhVal)
        }
    case conditionparser.NotExpression:
        subExpression := v.Expression
        // Note, because of not() brackets, can treat as top level
        subExpressionString := walk(subExpression, false)

        return fmt.Sprintf("not(%v)", subExpressionString)
    case conditionparser.PrecedenceExpression:
        subExpressionString := walk(v.Expression, false)

        return fmt.Sprintf("(%v)", subExpressionString)
    case conditionparser.ValuePathExpression:
        return walk(v.VPathFilter, true)
    // case idqlCondition.AttributeExpression:
    default:
        return v.String()
    }
}
