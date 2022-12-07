package filter

import (
	"errors"

	"strings"
)

func ParseFilter(expression string) (Expression, error) {
	return parseFilterSub(expression, "")
}

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
					//ignore brackets in values
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
						switch subFilter.(type) {
						case AttributeExpression:
							var filter Expression
							if isNot {
								filter = NotExpression{
									Expression: subFilter,
								}
							} else {
								filter = PrecedenceExpression{Expression: subFilter}
							}
							clauses = append(clauses, filter)

						default:
							if isNot {
								clauses = append(clauses, NotExpression{Expression: subFilter})
							} else {
								clauses = append(clauses, PrecedenceExpression{Expression: subFilter})
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
					if valPathCnt > 1 {
						return nil, errors.New("invalid filter: A second '[' was detected while loocking for a ']' in an attribute value filter")
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
						clause := ValuePathExpression{
							Attribute:   name,
							VPathFilter: subExpression,
						}
						clauses = append(clauses, clause)

						if charPos+1 < len(expression) && expRunes[charPos+1] != ' ' {
							charPos++
							for charPos < len(expression) && expRunes[charPos] != ' ' {
								charPos++
							}
						}
						// reset for the next phrase
						vPathStartIndex = -1
						wordIndex = -1
						isAttr = false
					}
				default:
				}
				// only increment if we are still processing ( ) phrases
				if valPathCnt > 0 {
					charPos++
				}
			}
			if charPos == len(expression) && valPathCnt > 0 {
				return nil, errors.New("invalid filter: missing close ']' bracket")
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
							attrFilter := AttributeExpression{
								AttributePath: attr,
								Operator:      CompareOperator("pr"),
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
							if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
								value = value[1 : len(value)-1]
							}
							wordIndex = -1
							filterAttr := attr
							if parentAttr != "" {
								filterAttr = parentAttr + "." + attr
							}
							attrFilter := AttributeExpression{
								AttributePath: filterAttr,
								Operator:      CompareOperator(strings.ToLower(cond)),
								CompareValue:  value,
							}
							attr = ""
							isAttr = false
							cond = ""
							isExpr = false
							isValue = false
							clauses = append(clauses, attrFilter)
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
				return nil, errors.New("invalid filter: missing open '(' bracket")
			}
			break
		case ']':
			if isQuote || isValue {
				break
			}
			if valPathCnt == 0 {
				return nil, errors.New("invalid filter: missing open '[' bracket")
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
			clauses = []Expression{LogicalExpression{
				Operator: oper,
				Left:     clauses[0],
				Right:    clauses[1],
			}}
			isLogic = false
		}
	}

	if bracketCount > 0 {
		return nil, errors.New("invalid filter: missing close ')' bracket")
	}
	if valPathCnt > 0 {
		return nil, errors.New("invalid filter: missing ']' bracket")
	}
	if wordIndex > -1 && charPos == len(expression) {
		filterAttr := attr
		if parentAttr != "" {
			filterAttr = parentAttr + "." + attr
		}
		if isAttr && cond != "" {
			value = expression[wordIndex:]
			if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
				value = value[1 : len(value)-1]
			}

			attrexp := AttributeExpression{
				AttributePath: filterAttr,
				Operator:      CompareOperator(strings.ToLower(cond)),
				CompareValue:  value,
			}
			clauses = append(clauses, attrexp)
		} else {
			// a presence match at the end of the filter string
			if isAttr {
				cond = expression[wordIndex:]
			}
			attrexp := AttributeExpression{
				AttributePath: filterAttr,
				Operator:      CompareOperator("pr"),
			}
			clauses = append(clauses, attrexp)

		}
	}

	if isLogic && len(clauses) == 2 {
		var oper LogicalOperator
		if isAnd {
			oper = "and"
		} else {
			oper = "or"
		}
		return LogicalExpression{
			Operator: oper,
			Left:     clauses[0],
			Right:    clauses[1],
		}, nil
	}
	if len(clauses) == 1 {
		return clauses[0], nil
	}

	return nil, errors.New("unknown filter exception. Missing and/or clause(?)")
}
