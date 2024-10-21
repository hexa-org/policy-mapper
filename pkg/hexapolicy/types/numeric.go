package types

import (
	"strconv"
)

type Numeric struct {
	value float64
	raw   string
}

func NewNumeric(value string) (Value, error) {
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return nil, err
	}
	return Numeric{n, value}, nil
}

func (n Numeric) Value() interface{} {
	return n.value
}

func (n Numeric) String() string {
	return n.raw
}

func (n Numeric) OperandType() int {
	return RelTypeNumber
}
