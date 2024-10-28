package policyInfoModel

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	hexaTypes "github.com/hexa-org/policy-mapper/pkg/hexapolicy/types"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
)

func TestParsePhotoSchema(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	fileBytes, err := os.ReadFile(filepath.Join(file, "../test", "photoSchema.json"))
	assert.NoError(t, err)

	namespaces, err := ParseSchemaFile(fileBytes)
	assert.NoError(t, err)
	assert.NotNil(t, namespaces)

	schemas := *namespaces
	app, ok := schemas["PhotoApp"]
	if !ok {
		assert.Fail(t, "Expected PhotoApp Schema")
	}
	assert.NotNil(t, app)

	principleTypes := *app.Actions["viewPhoto"].AppliesTo.PrincipalTypes
	assert.Contains(t, principleTypes, "User")

	photoType := app.EntityTypes["Photo"]
	assert.NotNil(t, photoType)
	assert.Equal(t, "Record", photoType.Shape.Type)
	assert.Equal(t, "Account", photoType.Shape.Attributes["account"].Name)

	personType := app.CommonTypes["PersonType"]
	assert.NotNil(t, personType)
	assert.Equal(t, "Long", personType.Attributes["age"].Type)
}

func TestParseCmvSchema(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	fileBytes, err := os.ReadFile(filepath.Join(file, "../test", "cmvSchemaTest.json"))
	assert.NoError(t, err)

	namespaces, err := ParseSchemaFile(fileBytes)
	assert.NoError(t, err)
	assert.NotNil(t, namespaces)

	schemas := *namespaces
	app, ok := schemas["PhotoApp"]
	if !ok {
		assert.Fail(t, "Expected PhotoApp Schema")
	}
	assert.NotNil(t, app)

	entity := hexaTypes.ParseEntity("User:userId")
	aType := app.FindAttrType(*entity)

	assert.NotNil(t, aType)
	assert.Equal(t, TypeString, aType.Type)

	entityEmails := hexaTypes.ParseEntity("User:emails.primary")
	aType = app.FindAttrType(*entityEmails)
	assert.NotNil(t, aType)
	assert.Equal(t, TypeBool, aType.Type)

	entityUserName := hexaTypes.ParseEntity("User:name")
	aType = app.FindAttrType(*entityUserName)
	assert.NotNil(t, aType)
	assert.Equal(t, TypeRecord, aType.Type)

	entityNameFamily := hexaTypes.ParseEntity("User:name.familyName")
	aType = app.FindAttrType(*entityNameFamily)
	assert.NotNil(t, aType)
	assert.Equal(t, TypeString, aType.Type)

	entityBad := hexaTypes.ParseEntity("User:name.bad")
	aType = app.FindAttrType(*entityBad)
	assert.Nil(t, aType)

	entityBadType := hexaTypes.ParseEntity("Bad:name")
	aType = app.FindAttrType(*entityBadType)
	assert.Nil(t, aType)
}

func TestParseHealthSchema(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	fileBytes, err := os.ReadFile(filepath.Join(file, "../test", "healthSchema.json"))
	assert.NoError(t, err)

	namespace, err := ParseSchemaFile(fileBytes)
	assert.NoError(t, err)
	assert.NotNil(t, namespace)

	schemas := *namespace
	app, ok := schemas["HealthCareApp"]
	if !ok {
		assert.Fail(t, "Expected HealthcareApp Schema")
	}
	assert.NotNil(t, app)

	userType := app.EntityTypes["User"]
	assert.NotNil(t, userType)
	assert.Contains(t, userType.MemberOfTypes, "Role")
	assert.Equal(t, "Record", userType.Shape.Type)
	assert.Empty(t, userType.Shape.Attributes)

	creatAppointmentAction := app.Actions["createAppointment"]
	assert.NotNil(t, creatAppointmentAction)
	assert.Contains(t, *creatAppointmentAction.AppliesTo.PrincipalTypes, "User")

	context := creatAppointmentAction.AppliesTo.Context
	assert.NotNil(t, context)
	assert.Equal(t, "Record", context.Type)
	assert.Equal(t, "User", context.Attributes["referrer"].Name)
}

func TestJsonSchemaIdql(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	idqlSchemaBytes, err := os.ReadFile(filepath.Join(file, "..", "resources", "idql.jschema"))
	assert.NoError(t, err)
	assert.NotNil(t, idqlSchemaBytes)
	schema, err := jsonschema.UnmarshalJSON(strings.NewReader(string(idqlSchemaBytes)))

	assert.NoError(t, err)
	assert.NotNil(t, schema)

	healthPath := filepath.Join(file, "..", "test", "healthSchema.json")
	healthSchemaBytes, err := os.ReadFile(healthPath)
	assert.NoError(t, err)
	assert.NotNil(t, healthSchemaBytes)

	healthSchema, err := jsonschema.UnmarshalJSON(strings.NewReader(string(healthSchemaBytes)))
	assert.NoError(t, err)
	assert.NotNil(t, healthSchema)

	c := jsonschema.NewCompiler()
	err = c.AddResource(healthPath, healthSchema)
	assert.NoError(t, err)

	sch, err := c.Compile(healthPath)
	assert.NoError(t, err)
	assert.NotNil(t, sch)

	healthEntitiesPath := filepath.Join(file, "..", "test", "healthEntities.json")
	healthDataBytes, err := os.ReadFile(healthEntitiesPath)
	assert.NoError(t, err)
	healthInst, err := jsonschema.UnmarshalJSON(strings.NewReader(string(healthDataBytes)))
	err = sch.Validate(healthInst)
	assert.NoError(t, err)
}
