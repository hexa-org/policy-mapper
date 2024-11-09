package types

import (
	"time"
)

type Date struct {
	value *time.Time
}

func NewDate(value string) (ComparableValue, error) {
	val, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}
	return Date{&val}, nil
}

func (d Date) ValueType() int {
	return TypeDate
}

func (d Date) Value() interface{} {
	return *d.value
}

func (d Date) String() string {
	return d.value.Format(time.RFC3339)
}

func (d Date) LessThan(obj ComparableValue) (bool, bool) {
	switch val := obj.(type) {
	case Date:
		left := *d.value
		right := *val.value
		return left.Before(right), false
	default:
		return false, true
	}
}

func (d Date) Equals(obj ComparableValue) bool {
	return d.value.Equal(obj.Value().(time.Time))
}
