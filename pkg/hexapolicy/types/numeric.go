package types

import (
	"strconv"
)

type Numeric struct {
	value *float64
	raw   string
}

func NewNumeric(value string) (ComparableValue, error) {
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return nil, err
	}
	return Numeric{&n, value}, nil
}

func (n Numeric) Value() interface{} {
	return *n.value
}

func (n Numeric) String() string {
	return n.raw
}

func (n Numeric) ValueType() int {
	return TypeNumber
}

func (n Numeric) LessThan(obj ComparableValue) (bool, bool) {
	switch val := obj.(type) {
	case Numeric:
		left := *n.value
		right := *val.value
		return left < right, false
	case String:
		left := n.String()
		right := val.value
		return left < right, false
	default:
		return false, true
	}
}

func (n Numeric) Equals(obj ComparableValue) bool {
	return n.Value() == obj.Value()
}
