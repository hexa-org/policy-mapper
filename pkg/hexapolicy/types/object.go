package types

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Object struct {
	valMap map[string]Value
}

func (o *Object) UnmarshalJSON(data []byte) error {
	if data == nil || len(data) == 0 {
		return nil
	}

	var fieldMap map[string]*json.RawMessage
	if err := json.Unmarshal(data, &fieldMap); err != nil {
		return err
	}
	o.valMap = make(map[string]Value, len(fieldMap))
	// var valMap map[string]Value
	for k, v := range fieldMap {
		valBytes, _ := v.MarshalJSON()
		if valBytes != nil {
			value, err := ParseValue(string(valBytes))
			if err != nil {
				return err
			}
			o.valMap[k] = value
		}

	}
	return nil
}

func (o Object) GetAttribute(name string) (Value, bool) {
	val, ok := o.valMap[name]
	return val, ok
}

func (o Object) String() string {
	sb := strings.Builder{}
	sb.WriteString("{")
	i := 0
	for k, v := range o.valMap {
		if i > 0 {
			sb.WriteString(",")
		}
		i++
		sb.WriteString(fmt.Sprintf("\"%s\":", k))
		sb.WriteString(v.String())
	}
	sb.WriteString("}")
	return sb.String()
}

func (o Object) ValueType() int {
	return TypeObject
}

func (o Object) Value() interface{} {
	return o.valMap
}

func ParseObject(jsonString string) (Value, error) {
	var obj Object

	err := json.Unmarshal([]byte(jsonString), &obj)
	if err != nil {
		return nil, err
	}

	return &obj, nil
}
