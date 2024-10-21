package types

import (
	"strconv"
	"strings"
)

type String struct {
	value string
}

func NewString(value string) Value {
	if strings.HasPrefix(value, "\"") {
		return String{value[1 : len(value)-1]}
	}
	return String{value}
}

func (s String) OperandType() int {
	return RelTypeString
}

func (s String) Value() interface{} {
	return s.value
}

func (s String) String() string {
	return strconv.Quote(s.value)
}
