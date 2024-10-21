package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBoolean(t *testing.T) {

	value, err := ParseValue("true")
	assert.NoError(t, err)

	assert.IsType(t, Boolean{}, value)

	assert.Equal(t, RelTypeBool, value.OperandType())
	assert.Equal(t, true, value.Value())

	assert.Equal(t, "true", value.String())
}

func TestString(t *testing.T) {
	value, err := ParseValue("\"1234 quick brown fox\"")
	assert.NoError(t, err)
	assert.IsType(t, String{}, value)

	assert.Equal(t, RelTypeString, value.OperandType())
	assert.Equal(t, "1234 quick brown fox", value.Value())
	assert.Equal(t, "\"1234 quick brown fox\"", value.String())
}

func TestNumeric(t *testing.T) {
	value, err := ParseValue("365")
	assert.NoError(t, err)
	assert.IsType(t, Numeric{}, value)
	assert.Equal(t, RelTypeNumber, value.OperandType())
	assert.Equal(t, float64(365), value.Value())
	assert.Equal(t, "365", value.String())

	decValue, err := ParseValue("3.1415")
	assert.NoError(t, err)
	assert.IsType(t, Numeric{}, decValue)
	assert.Equal(t, float64(3.1415), decValue.Value())
	assert.Equal(t, "3.1415", decValue.String())
}

func TestDate(t *testing.T) {
	value, err := ParseValue("2011-05-13T04:42:34Z")
	assert.NoError(t, err)
	assert.IsType(t, Date{}, value)
	assert.Equal(t, RelTypeDate, value.OperandType())
	assert.Equal(t, "2011-05-13T04:42:34Z", value.String())
	date, _ := time.Parse(time.RFC3339, "2011-05-13T04:42:34Z")
	assert.Equal(t, date, value.Value())
}

func TestEntity(t *testing.T) {
	value, err := ParseValue("user:name.surname")
	assert.NoError(t, err)
	assert.IsType(t, Entity{}, value)
	assert.Equal(t, RelTypeVariable, value.OperandType())
	assert.Equal(t, "user:name.surname", value.String())
	assert.Equal(t, "user", value.(Entity).GetType())
}
