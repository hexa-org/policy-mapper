package types

import "strings"

type Boolean struct {
	value bool
}

func NewBoolean(value string) Value {
	if strings.EqualFold(value, "true") {
		return Boolean{true}
	}
	return Boolean{false}
}

func (e Boolean) OperandType() int {
	return RelTypeBool
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
