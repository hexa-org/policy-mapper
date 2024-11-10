package types

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTypes(t *testing.T) {

	testTime, _ := time.Parse(time.RFC3339, "2011-05-13T04:42:34Z")
	testFloat := float64(4)
	tests := []struct {
		name       string
		value      string
		expected   Value
		moreValue  string
		compatTest string
		lessTest   bool
	}{
		{"Boolean",
			"false",
			Boolean{value: false},
			"true",
			"123",
			true,
		},
		{
			"Date",
			"2011-05-13T04:42:34Z",
			Date{&testTime},
			"2011-05-13T04:50:34Z",
			"1",
			true,
		}, {
			"Numeric",
			"4",
			Numeric{&testFloat, "4"},
			"5.4",
			"2011-05-13T04:50:34Z",
			true,
		},
		{
			"NumericAndString",
			"4",
			Numeric{&testFloat, "4"},
			"\"ab\"",
			"2011-05-13T04:50:34Z",
			true,
		},
		{
			"Strings",
			"\"abc\"",
			String{value: "abc"},
			"\"zzz\"",
			"2011-05-13T04:50:34Z",
			true,
		},
		{
			"Arrays",
			"[\"a\", \"b\", \"c\"]",
			Array{[]ComparableValue{String{"a"}, String{"b"}, String{"c"}}},
			"",
			"",
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := ParseValue(test.value)
			assert.NoError(t, err)

			// test equals
			assert.Equal(t, test.expected, value)

			assert.Equal(t, test.value, value.String(), "Check String() function returns initial string value")

			if test.lessTest { // Entity, Array, Object don't support less than

				assert.Implements(t, (*ComparableValue)(nil), value, "Check value is comparable")
				cvalue := value.(ComparableValue)
				// Test that a value is equal to itself
				assert.True(t, cvalue.Equals(cvalue))

				// Test that a value is not less than itself
				selfLess, notOk := cvalue.LessThan(cvalue)
				assert.False(t, notOk)
				assert.False(t, selfLess, "Check the a value cannot be less than itself")

				moreTestVal, err := ParseValue(test.moreValue)
				assert.NoError(t, err)

				// Values should not be equal
				assert.False(t, cvalue.Equals(moreTestVal.(ComparableValue)))

				// Should be less than
				isLess, notOk := cvalue.LessThan(moreTestVal.(ComparableValue))
				assert.False(t, notOk)
				assert.True(t, isLess, "Check less than is true")

				isMore, notOk := moreTestVal.(ComparableValue).LessThan(cvalue)
				assert.False(t, isMore, "Check more than is false")

				compatibleTest, err := ParseValue(test.compatTest)
				assert.NoError(t, err)

				_, notOk = cvalue.LessThan(compatibleTest.(ComparableValue))
				assert.True(t, notOk, "Check result not comparable")
			}
		})
	}

	isPresent, notOk := CompareValues(nil, nil, PR)
	assert.False(t, notOk)
	assert.False(t, isPresent)

	isPresent, notOk = CompareValues(NewString("\"\""), nil, PR)
	assert.False(t, notOk)
	assert.False(t, isPresent)

	isPresent, notOk = CompareValues(NewString("a"), nil, PR)
	assert.False(t, notOk)
	assert.True(t, isPresent)
}

func TestBoolean(t *testing.T) {

	value, err := ParseValue("true")
	assert.NoError(t, err)

	assert.IsType(t, Boolean{}, value)

	assert.Equal(t, TypeBool, value.ValueType())
	assert.Equal(t, true, value.Value())

	assert.Equal(t, "true", value.String())

	value2 := NewBoolean("false")
	lessThan, notOk := value.(ComparableValue).LessThan(value2)
	assert.False(t, lessThan)
	assert.False(t, notOk)
}

func TestString(t *testing.T) {
	// First test empty string
	value, err := ParseValue("")
	assert.NoError(t, err)
	assert.Equal(t, TypeString, value.ValueType())
	assert.Equal(t, "", value.Value())

	value, err = ParseValue("\"1234 quick brown fox\"")
	assert.NoError(t, err)
	assert.IsType(t, String{}, value)

	assert.Equal(t, TypeString, value.ValueType())
	assert.Equal(t, "1234 quick brown fox", value.Value())
	assert.Equal(t, "\"1234 quick brown fox\"", value.String())

	value2 := NewString("zzzz")
	isLess, notOk := value.(ComparableValue).LessThan(value2)
	assert.False(t, notOk)
	assert.True(t, isLess)

	isEqual := value.(ComparableValue).Equals(value2)
	assert.False(t, isEqual)

}

func TestNumeric(t *testing.T) {
	value, err := ParseValue("365")
	assert.NoError(t, err)
	assert.IsType(t, Numeric{}, value)
	assert.Equal(t, TypeNumber, value.ValueType())
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
	assert.Equal(t, TypeDate, value.ValueType())
	assert.Equal(t, "2011-05-13T04:42:34Z", value.String())
	date, _ := time.Parse(time.RFC3339, "2011-05-13T04:42:34Z")
	assert.Equal(t, date, value.Value())

	errVal, err := NewDate("2011-05")
	assert.Error(t, err)
	assert.Nil(t, errVal)
}

func TestEntity(t *testing.T) {
	value, err := ParseValue("user:name.surname")
	assert.NoError(t, err)
	assert.IsType(t, Entity{}, value)
	assert.Equal(t, TypeVariable, value.ValueType())
	assert.Equal(t, "user:name.surname", value.String())
	assert.Equal(t, "user", value.(Entity).GetType())

	value2 := ParseEntity("PhotoApp:Photo:\"myphoto.jpg\"")
	assert.NotNil(t, value2)
	assert.Equal(t, "myphoto.jpg", value2.GetId())
	assert.Equal(t, "Photo", value2.GetType())
	assert.Equal(t, "PhotoApp", value2.GetNamespace("ab"))
}

func TestEmpty(t *testing.T) {
	value, err := ParseValue("user:name.surname")
	assert.NoError(t, err)
	assert.NotNil(t, value)
	assert.IsType(t, Entity{}, value)

	evalue := NewEmptyValue(value.(Entity))

	assert.Equal(t, TypeUnassigned, evalue.ValueType())
	assert.Nil(t, evalue.Value())
	assert.Equal(t, "", evalue.String())
	assert.Equal(t, "user:name.surname", (evalue.(EmptyValue)).GetPath())

	dvalue, _ := NewDate("2011-05-13T04:42:34Z")
	_, notOk := evalue.LessThan(dvalue)
	assert.True(t, notOk)

	assert.True(t, evalue.Equals(evalue))
	assert.False(t, evalue.Equals(dvalue))
}

func TestArray(t *testing.T) {
	value, err := ParseValue("[1,2,3]")
	assert.NoError(t, err)
	assert.IsType(t, Array{}, value)
	assert.Equal(t, TypeArray, value.ValueType())
	assert.IsType(t, []ComparableValue{}, value.Value())
	vals := value.Value().([]ComparableValue)
	val2 := vals[1]
	assert.Equal(t, float64(2), val2.Value())
}

func TestObject(t *testing.T) {
	jsonText := `{"a":"b","c":1,"sub":{"name":"susie"}}`
	val, err := ParseObject(jsonText)
	assert.NoError(t, err)
	assert.NotNil(t, val)

	subVal, ok := val.(*Object).GetAttribute("sub")
	assert.True(t, ok)
	assert.IsType(t, &Object{}, subVal)

	copyVal, err := ParseValue(val.String())
	assert.NoError(t, err)
	assert.True(t, reflect.DeepEqual(val, copyVal))

	errVal, err := ParseValue("{\"a\":{bleh:123}}")
	assert.Error(t, err)
	assert.Nil(t, errVal)

	assert.Equal(t, TypeObject, val.ValueType())
	vals := val.Value()
	assert.Len(t, vals, 3)
	assert.IsType(t, map[string]Value{}, vals)
}

func TestCompareValueStringOps(t *testing.T) {

	date, _ := NewDate("2011-05-13T04:42:34Z")
	compStart := NewString("2011")
	compEnd := NewString("Z")

	match, notOk := CompareValues(date, compStart, SW)
	assert.True(t, match)
	assert.False(t, notOk)

	match, notOk = CompareValues(date, compEnd, SW)
	assert.False(t, match)
	assert.False(t, notOk)

	match, notOk = CompareValues(date, compStart, EW)
	assert.False(t, match)
	assert.False(t, notOk)

	match, notOk = CompareValues(date, compEnd, EW)
	assert.True(t, match)
	assert.False(t, notOk)

	stringTest := NewString("abc123")
	stringStart := NewString("abc")
	stringEnd := NewString("123")

	match, notOk = CompareValues(stringTest, stringStart, SW)
	assert.True(t, match)
	assert.False(t, notOk)

	match, notOk = CompareValues(stringTest, stringEnd, SW)
	assert.False(t, match)

	match, notOk = CompareValues(stringTest, stringEnd, EW)
	assert.True(t, match)
}
func TestComparableValue(t *testing.T) {
	tests := []struct {
		name       string
		left       string
		right      string
		isEqual    bool
		isLess     bool
		notOk      bool
		doContains bool
		isContains bool
		doIn       bool
		isIn       bool
	}{
		{"Strings",
			"\"abc\"",
			"\"def\"",
			false,
			true,
			false,
			true,
			false,
			true,
			false,
		},
		{"String Contains",
			"\"abcdef\"",
			"\"def\"",
			false,
			true,
			false,
			true,
			true,
			true,
			false,
		},
		{"String In",
			"\"abc\"",
			"\"abcdef\"",
			false,
			true,
			false,
			true,
			false,
			true,
			true,
		},
		{"Number",
			"12",
			"12",
			true,
			false,
			false,
			false,
			false,
			false,
			true,
		},
		{"LessAndGreater",
			"12",
			"34.5",
			false,
			true,
			false,
			false,
			false,
			false,
			true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left, err := ParseValue(test.left)
			assert.NoError(t, err)
			cleft := left.(ComparableValue)
			right, err := ParseValue(test.right)
			assert.NoError(t, err)
			cright := right.(ComparableValue)

			// Do it directly
			assert.Equal(t, test.isEqual, cleft.Equals(cright))
			isLess, notOk := CompareValues(cleft, cright, LT)
			assert.Equal(t, test.notOk, notOk)
			assert.Equal(t, test.isLess, isLess)

			isLessEqual, notOk := CompareValues(cleft, cright, LE)
			testLessOrEqual := test.isLess || test.isEqual
			assert.Equal(t, test.notOk, notOk)
			assert.Equal(t, testLessOrEqual, isLessEqual)

			isGreater, notOk := CompareValues(cright, cleft, GT)
			assert.Equal(t, test.notOk, notOk)
			assert.Equal(t, test.isLess, isGreater)

			isGreaterEqual, notOk := CompareValues(cright, cleft, GE)
			assert.Equal(t, test.notOk, notOk)
			assert.Equal(t, testLessOrEqual, isGreaterEqual)

			isEqual, notOk := CompareValues(cleft, cright, EQ)
			assert.Equal(t, test.notOk, notOk)
			assert.Equal(t, test.isEqual, isEqual)

			isNotEqual, notOk := CompareValues(cleft, cright, NE)
			assert.Equal(t, test.notOk, notOk)
			assert.Equal(t, !test.isEqual, isNotEqual)

			if test.doContains {
				isContains, notOK := CompareValues(cleft, cright, CO)
				assert.Equal(t, test.notOk, notOK)
				assert.Equal(t, test.isContains, isContains)
			}

			if test.doIn {
				isIn, notOK := CompareValues(cleft, cright, IN)
				assert.Equal(t, test.notOk, notOK)
				assert.Equal(t, test.isIn, isIn)
			}

		})
	}
}

func TestTypeName(t *testing.T) {
	assert.Equal(t, "Entity", TypeName(TypeVariable))
	assert.Equal(t, "String", TypeName(TypeString))
	assert.Equal(t, "Number", TypeName(TypeNumber))
	assert.Equal(t, "Date", TypeName(TypeDate))
	assert.Equal(t, "Bool", TypeName(TypeBool))
	assert.Equal(t, "Array", TypeName(TypeArray))
	assert.Equal(t, "Object", TypeName(TypeObject))
	assert.Equal(t, "Unassigned", TypeName(TypeUnassigned))
	assert.Equal(t, "Unknown", TypeName(100))
}
