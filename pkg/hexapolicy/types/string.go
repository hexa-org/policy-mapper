package types

import (
	"strconv"
	"strings"
)

type String struct {
	value string
}

func NewString(value string) ComparableValue {
	if strings.HasPrefix(value, "\"") {
		return String{value[1 : len(value)-1]}
	}
	return String{value}
}

func (s String) ValueType() int {
	return TypeString
}

func (s String) Value() interface{} {
	return s.value
}

func (s String) String() string {
	return strconv.Quote(s.value)
}

func (s String) LessThan(obj ComparableValue) (bool, bool) {
	switch val := obj.(type) {
	case String:
		return strings.Compare(s.value, val.value) == -1, false
	case Numeric:
		return strings.Compare(s.value, val.String()) == -1, false
	default:
		return false, true
	}
}

func (s String) Equals(obj ComparableValue) bool {
	rValue := obj.String()
	if strings.HasPrefix(rValue, "\"") {
		rValue, _ = strconv.Unquote(rValue)
	}
	return strings.EqualFold(s.value, rValue)
}
