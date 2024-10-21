package types

import "time"

type Date struct {
	value time.Time
}

func NewDate(value string) (Value, error) {
	val, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}
	return Date{val}, nil
}

func (d Date) OperandType() int {
	return RelTypeDate
}

func (d Date) Value() interface{} {
	return d.value
}

func (d Date) String() string {
	return d.value.Format(time.RFC3339)
}
