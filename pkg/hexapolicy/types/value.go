package types

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	RelTypeVariable = iota
	RelTypeString
	RelTypeNumber
	RelTypeDate
	RelTypeBool
)

type Value interface {
	fmt.Stringer // returns the string value
	OperandType() int
	Value() interface{} // returns the raw value
	// Compare(op parser.CompareOperator,value Value) (bool, error)
}

func ParseValue(val string) (Value, error) {
	if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
		return NewString(val), nil
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

	// still might be an unquoted literal!

	return *ParseEntity(val), nil
}
