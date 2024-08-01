package schema

import (
    "os"
    "path/filepath"
    "runtime"
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestParsePhotoSchema(t *testing.T) {
    _, file, _, _ := runtime.Caller(0)
    fileBytes, err := os.ReadFile(filepath.Join(file, "../test", "photoSchema.json"))
    assert.NoError(t, err)

    namespace, err := ParseSchemaFile(fileBytes)
    assert.NoError(t, err)
    assert.NotNil(t, namespace)

    schemas := *namespace
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
