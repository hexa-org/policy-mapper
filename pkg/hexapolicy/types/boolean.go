package types

import (
	"strings"
)

type Boolean struct {
	value bool
}

func NewBoolean(value string) ComparableValue {
	if strings.EqualFold(value, "true") {
		return Boolean{true}
	}
	return Boolean{false}
}

func (e Boolean) ValueType() int {
	return TypeBool
}

func (e Boolean) Value() interface{} {
	return e.value
}

func (b Boolean) String() string {
	if b.value {
		return "true"
	}
	return "false"
}

// LessThan is defined such that false is less than true (0 is less than 1)
func (e Boolean) LessThan(obj ComparableValue) (bool, bool) {
	if obj.ValueType() != TypeBool {
		return false, true
	}
	cVal := obj.Value().(bool)
	if e.value == cVal {
		return false, false
	} // values are equal
	return e.value == false, false
}

func (e Boolean) Equals(obj ComparableValue) bool {
	return e.value == obj.Value()
}
