package parser

import (
	"errors"

	"strings"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/types"
)

// ParseFilter parses a SCIM-like (RFC7644) filter expression string and returns an AST as an Expression
func ParseFilter(expression string) (Expression, error) {
	return parseFilterSub(expression, "")
}

// parseFilterSub is the main lexer for converting strings into Expressions
func parseFilterSub(expression string, parentAttr string) (Expression, error) {
	bracketCount := 0
	bracketIndex := -1
	valPathCnt := 0
	vPathStartIndex := -1
	wordIndex := -1
	var clauses []Expression
	cond := ""

	isLogic := false
	isAnd := false
	isNot := false
	isAttr := false
	attr := ""
	isExpr := false
	isValue := false
	value := ""
	isQuote := false

	expRunes := []rune(expression)
	var charPos int
	var vpe *ValuePathExpression
	for charPos = 0; charPos < len(expRunes); charPos++ {

		c := expRunes[charPos]
		switch c {
		case '(':
			if isQuote || isValue {
				break
			}
			bracketCount++
			if bracketCount == 1 {
				bracketIndex = charPos
			}
			charPos++
			quotedBracket := false
			for charPos < len(expRunes) && bracketCount > 0 {
				cc := expRunes[charPos]
				switch cc {
				case '"':
					quotedBracket = !quotedBracket
					break
				case '(':
					if quotedBracket {
						break
					}
					bracketCount++
					break
				case ')':
					// ignore brackets in values
					if quotedBracket {
						break
					}
					bracketCount--
					if bracketCount == 0 {
						subExpression := expression[bracketIndex+1 : charPos]
						subFilter, err := parseFilterSub(subExpression, parentAttr)
						if err != nil {
							return nil, err
						}
						var filter Expression
						sFilter := subFilter
						switch sFilter.(type) {
						case AttributeExpression:

							if isNot {
								filter = NotExpression{
									Expression: sFilter,
								}
							} else {
								filter = PrecedenceExpression{Expression: sFilter}
							}
							clauses = append(clauses, filter)

						default:
							if isNot {
								filter = NotExpression{Expression: sFilter}
								clauses = append(clauses, filter)
							} else {
								filter = PrecedenceExpression{Expression: sFilter}
								clauses = append(clauses, filter)
							}
						}
						bracketIndex = -1
					}

				}
				if bracketCount > 0 {
					charPos++
				}
			}
			break
		case '[':
			if isQuote || isValue {
				break
			}
			valPathCnt++
			if valPathCnt == 1 {
				vPathStartIndex = charPos
			}
			charPos++
			quotedSqBracket := false
			for charPos < len(expression) && valPathCnt > 0 {
				cc := expRunes[charPos]
				switch cc {
				case '"':
					quotedSqBracket = !quotedSqBracket
					break
				case '[':
					if quotedSqBracket {
						break
					}
					if valPathCnt >= 1 {
						return nil, errors.New("invalid IDQL idqlCondition: A second '[' was detected while looking for a ']' in a value path idqlCondition")
					}
					valPathCnt++
					break
				case ']':
					if quotedSqBracket {
						break
					}
					valPathCnt--
					if valPathCnt == 0 {
						name := expression[wordIndex:vPathStartIndex]
						valueFilterStr := expression[vPathStartIndex+1 : charPos]
						subExpression, err := parseFilterSub(valueFilterStr, "")
						if err != nil {
							return nil, err
						}
						// var filter Expression
						mainAttr := types.ParseEntity(name)
						vpe = &ValuePathExpression{
							Attribute:   *mainAttr,
							VPathFilter: subExpression,
						}
						// clauses = append(clauses, filter)

						if charPos+1 < len(expRunes) {
							cc := expRunes[charPos+1]
							if cc == '.' {
								charPos++
								subAttrStart := charPos + 1
								for charPos < len(expRunes) && expRunes[charPos] != ' ' {
									charPos++
								}
								subAttr := string(expRunes[subAttrStart:charPos])
								vpe.SubAttr = &subAttr
								charPos-- // reset back to space
							}
						}
						attr = name // this is just a place holder to trigger parsing operator next
						// reset for rest of phrase
						vPathStartIndex = -1
						wordIndex = -1
						isAttr = true
					}
				default:
				}
				// only increment if we are still processing ( ) phrases
				if valPathCnt > 0 {
					charPos++
				}
			}
			if charPos == len(expression) && valPathCnt > 0 {
				return nil, errors.New("invalid IDQL idqlCondition: Missing close ']' bracket")
			}
			break

		case ' ':
			if isQuote {
				break
			}
			// end of phrase
			if wordIndex > -1 {
				phrase := expression[wordIndex:charPos]
				if strings.EqualFold(phrase, "or") || strings.EqualFold(phrase, "and") {
					isLogic = true
					isAnd = strings.EqualFold(phrase, "and")
					wordIndex = -1
					break
				}
				if isAttr && attr == "" {
					attr = phrase
					wordIndex = -1
				} else {
					if isExpr && cond == "" {
						cond = phrase
						wordIndex = -1
						if strings.EqualFold(cond, "pr") {
							var attrFilter Expression
							var err error
							attrFilter, err = createExpression(attr, "pr", "", vpe)

							if err != nil {
								return nil, err
							}
							attr = ""
							isAttr = false
							cond = ""
							isExpr = false
							isValue = false
							clauses = append(clauses, attrFilter)
						}
					} else {
						if isValue {
							value = phrase
							if strings.HasSuffix(value, ")") && bracketCount == 0 {
								return nil, errors.New("invalid IDQL idqlCondition: Missing open '(' bracket")
							}
							/*
							   if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
							       value = value[1 : len(value)-1]
							   }
							*/
							wordIndex = -1
							filterAttr := attr
							if parentAttr != "" {
								filterAttr = parentAttr + "." + attr
							}

							var attrFilter Expression
							attrFilter, err := createExpression(filterAttr, cond, value, vpe)
							if err != nil {
								return nil, err
							}

							attr = ""
							isAttr = false
							cond = ""
							isExpr = false
							isValue = false
							clauses = append(clauses, attrFilter)
							vpe = nil
							break
						}
					}
				}
			}
			break
		case ')':
			if isQuote || isValue {
				break
			}
			if bracketCount == 0 {
				return nil, errors.New("invalid IDQL idqlCondition: Missing open '(' bracket")
			}
			break
		case ']':
			if isQuote || isValue {
				break
			}
			if valPathCnt == 0 {
				return nil, errors.New("invalid IDQL idqlCondition: Missing open '[' bracket")
			}
		case 'n', 'N':
			if !isValue {
				if charPos+3 < len(expression) &&
					strings.EqualFold(expression[charPos:charPos+3], "not") {
					isNot = true
					charPos = charPos + 2
					break
				}
			}

			// we want this to fall through to default in case it is an attribute starting with n
			if wordIndex == -1 {
				wordIndex = charPos
			}
			if !isAttr {
				isAttr = true
			} else {
				if !isExpr && attr != "" {
					isExpr = true
				} else {
					if !isValue && cond != "" {
						isValue = true
					}
				}
			}
			break
		default:
			if c == '"' {
				isQuote = !isQuote
			}
			if wordIndex == -1 {
				wordIndex = charPos
			}
			if !isAttr {
				isAttr = true
			} else {
				if !isExpr && attr != "" {
					isExpr = true
				} else {
					if !isValue && cond != "" {
						isValue = true
					}
				}
			}
		}
		// combine logic here
		if isLogic && len(clauses) == 2 {
			var oper LogicalOperator
			if isAnd {
				oper = "and"
			} else {
				oper = "or"
			}
			var filter Expression
			filter = LogicalExpression{
				Operator: oper,
				Left:     clauses[0],
				Right:    clauses[1],
			}
			clauses = []Expression{}
			clauses = append(clauses, filter)
			isLogic = false
		}
	}

	if bracketCount > 0 {
		return nil, errors.New("invalid IDQL idqlCondition: Missing close ')' bracket")
	}
	if valPathCnt > 0 {
		return nil, errors.New("invalid IDQL idqlCondition: Missing ']' bracket")
	}
	if wordIndex > -1 && charPos == len(expression) {
		filterAttr := attr
		if parentAttr != "" {
			filterAttr = parentAttr + "." + attr
		}
		if filterAttr == "" {
			return nil, errors.New("invalid IDQL idqlCondition: Incomplete expression")
		}
		if isAttr && cond != "" {
			value = expression[wordIndex:]
			if strings.HasSuffix(value, ")") && bracketCount == 0 {
				return nil, errors.New("invalid IDQL idqlCondition: Missing open '(' bracket")
			}
			/*  No need to remote quotes
			    if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
			        value = value[1 : len(value)-1]
			    }
			*/
			var filter Expression
			filter, err := createExpression(filterAttr, cond, value, vpe)
			if err != nil {
				return nil, err
			}
			vpe = nil
			clauses = append(clauses, filter)
		} else {
			// a presence match at the end of the idqlCondition string
			if isAttr {
				cond = expression[wordIndex:]
			}
			var filter Expression
			var err error
			filter, err = createExpression(filterAttr, "pr", "", vpe)
			if err != nil {
				return nil, err
			}
			clauses = append(clauses, filter)

		}
	}

	if isLogic && len(clauses) == 2 {
		var oper LogicalOperator
		if isAnd {
			oper = "and"
		} else {
			oper = "or"
		}
		var filter Expression
		filter = LogicalExpression{
			Operator: oper,
			Left:     clauses[0],
			Right:    clauses[1],
		}
		clauses = []Expression{}
		clauses = append(clauses, filter)

		return filter, nil
	}
	if len(clauses) == 1 {
		return clauses[0], nil
	}

	return nil, errors.New("invalid IDQL idqlCondition: Missing and/or clause")
}

func createExpression(attribute string, cond string, value string, vpe *ValuePathExpression) (Expression, error) {
	lCond := strings.ToLower(cond)
	op := CompareOperator(lCond)
	switch CompareOperator(lCond) {
	case EQ, NE, SW, EW, GT, LT, GE, LE, CO, IN, PR:
		if vpe != nil {
			vpe.Operator = &op
			var right types.Value
			var err error
			if op != PR {
				right, err = types.ParseValue(value)
				if err != nil {
					return nil, err
				}
				vpe.CompareValue = right
			}
			return *vpe, nil
		}
		return NewAttributeExpression(attribute, CompareOperator(lCond), value)

	default:
		return nil, errors.New("invalid IDQL idqlCondition: Unsupported comparison operator: " + cond)
	}
}
