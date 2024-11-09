package types

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	TypeVariable = iota
	TypeString
	TypeNumber
	TypeDate
	TypeBool
	TypeArray
	TypeObject
	TypeUnassigned
)

// TypeName returns a string value converting the Value.ValueType() response into a string. Used for error messages
func TypeName(i int) string {
	switch i {
	case TypeVariable:
		return "Entity"
	case TypeString:
		return "String"
	case TypeNumber:
		return "Number"
	case TypeDate:
		return "Date"
	case TypeBool:
		return "Bool"
	case TypeArray:
		return "Array"
	case TypeObject:
		return "Object"
	case TypeUnassigned:
		return "Unassigned"
	}
	return "Unknown"
}

// These constants are intended to match the IDQL filter parser constants (duplicated here to prevent dependence loop)
const (
	// PR is an abbreviation for 'present'.
	PR string = "pr"
	// EQ is an abbreviation for 'equals'.
	EQ string = "eq"
	// NE is an abbreviation for 'not equals'.
	NE string = "ne"
	// CO is an abbreviation for 'contains'.
	CO string = "co"
	// IN is an abbreviation for 'in'.
	IN string = "in"
	// SW is an abbreviation for 'starts with'.
	SW string = "sw"
	// EW an abbreviation for 'ends with'.
	EW string = "ew"
	// GT is an abbreviation for 'greater than'.
	GT string = "gt"
	// LT is an abbreviation for 'less than'.
	LT string = "lt"
	// GE is an abbreviation for 'greater or equal than'.
	GE string = "ge"
	// LE is an abbreviation for 'less or equal than'.
	LE string = "le"

	// IS allows comparison of Object/Resource Types - added for Cedar compat
	IS string = "is"
)

// Value defines the interface for all parsable operators in an IDQL filter.
type Value interface {
	fmt.Stringer // returns the string value
	ValueType() int
	Value() interface{} // returns the raw value
	// Compare(op parser.CompareOperator,value Value) (bool, error)
}

// ComparableValue is a subset of operators that can be used in LessThan or Equals comparison and have actual data
// values. Typically, an operator like an Entity is converted into a comparable value before calling CompareValues.
type ComparableValue interface {
	Value
	LessThan(obj ComparableValue) (result bool, incompatible bool)
	Equals(obj ComparableValue) (result bool)
}

func CompareValues(left, right ComparableValue, op string) (bool, bool) {
	switch op {
	case PR:
		if left == nil || left.String() == "\"\"" {
			return false, false
		}
		return true, false
	case EQ:
		return left.Equals(right), false
	case NE:
		return !left.Equals(right), false
	case LT:
		return left.LessThan(right)

	case LE:
		if left.Equals(right) {
			return true, false
		}
		return left.LessThan(right)
	case GT:
		return right.LessThan(left)
	case GE:
		if left.Equals(right) {
			return true, false
		}
		return right.LessThan(left)
	case SW:
		lString := left.String()
		if strings.HasPrefix(lString, "\"") && strings.HasSuffix(lString, "\"") {
			lString, _ = strconv.Unquote(lString)
		}
		rString := right.String()
		if strings.HasPrefix(rString, "\"") && strings.HasSuffix(rString, "\"") {
			rString, _ = strconv.Unquote(rString)
		}
		return strings.HasPrefix(lString, rString), false
	case EW:
		lString := left.String()
		if strings.HasPrefix(lString, "\"") && strings.HasSuffix(lString, "\"") {
			lString, _ = strconv.Unquote(lString)
		}
		rString := right.String()
		if strings.HasPrefix(rString, "\"") && strings.HasSuffix(rString, "\"") {
			rString, _ = strconv.Unquote(rString)
		}
		return strings.HasSuffix(lString, rString), false
	case CO: // Note: Arrays and objects are not comparable values
		switch val := left.(type) {
		case String:
			switch rVal := right.(type) {
			case String:
				return strings.Contains(val.value, rVal.value), false
			default:
				return strings.Contains(val.value, rVal.String()), false
			}
		default:
			return false, true
		}
	case IN:
		switch val := left.(type) {
		case String:
			switch rVal := right.(type) {
			case String:
				return strings.Contains(rVal.value, val.value), false
			default:
				return strings.Contains(rVal.String(), val.value), false
			}
		default:
			return false, true
		}
	}
	return false, true
}

func ParseValue(val string) (Value, error) {
	if val == "" {
		return NewString(""), nil
	}

	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
		return NewString(val), nil
	}

	if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
		return ParseArray(val)
	}
	if strings.HasPrefix(val, "{") && strings.HasSuffix(val, "}") {
		return ParseObject(val)
	}
	// is it a number?
	isNumeric := regexp.MustCompile("^[+\\-]?(?:(?:0|[1-9]\\d*)(?:\\.\\d*)?|\\.\\d+)(?:\\d[eE][+\\-]?\\d+)?$").MatchString(val)
	if isNumeric {
		return NewNumeric(val)
	}

	// is it a boolean
	if strings.EqualFold(val, "true") || strings.EqualFold(val, "false") {
		return NewBoolean(val), nil
	}

	// is it a time?
	_, err := time.Parse(time.RFC3339, val)
	if err == nil {
		return NewDate(val)
	}

	return *ParseEntity(val), nil
}
