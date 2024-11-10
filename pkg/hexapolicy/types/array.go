package types

import (
	"fmt"
	"strings"
)

type Array struct {
	values []ComparableValue
}

func NewArray(values []ComparableValue) Value {
	return Array{values}
}

func (a Array) String() string {
	sb := strings.Builder{}
	sb.WriteString("[")
	for i, value := range a.values {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(value.String())
	}
	sb.WriteString("]")
	return sb.String()
}

// ParseArray detects an array of comma separated values ofr values within square brackets
func ParseArray(s string) (Value, error) {
	val := strings.TrimSpace(s)

	val = strings.TrimPrefix(val, "[")
	val = strings.TrimSuffix(val, "]")

	vals := strings.Split(val, ",")
	values := make([]ComparableValue, len(vals))
	for i, item := range vals {
		iValue, err := ParseValue(item)
		if err != nil {
			return nil, err
		}
		switch v := iValue.(type) {
		case ComparableValue:
			values[i] = v
		default:
			return nil, fmt.Errorf("arrays cannot contain sub-arrays or objects: %s", s)
		}

	}
	return NewArray(values), nil
}

func (a Array) ValueType() int { return TypeArray }

func (a Array) Value() interface{} { return a.values }
