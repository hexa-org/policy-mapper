package types

// EmptyValue is a placeholder value for an entity that has no value. Instead of a value it captures the entity that
// was used to define it (typically for error responses)
type EmptyValue struct {
	entity Entity
}

func NewEmptyValue(pathEntity Entity) ComparableValue {
	return EmptyValue{pathEntity}
}

func (e EmptyValue) ValueType() int { return TypeUnassigned }

func (e EmptyValue) Value() interface{} {
	return nil
}

func (e EmptyValue) String() string {
	return ""
}

func (e EmptyValue) GetPath() string {
	return e.entity.String()
}

func (e EmptyValue) LessThan(_ ComparableValue) (bool, bool) {
	return false, true
}

func (s EmptyValue) Equals(obj ComparableValue) bool {
	return obj.Value() == nil
}
