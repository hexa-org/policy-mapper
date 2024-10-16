package pimValidate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/hexa-org/policy-mapper/models/formats/cedar"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/stretchr/testify/assert"
)

func TestValidate_Policy(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	testDirectory := filepath.Join(filepath.Dir(file), "../../../", "models/policyInfoModel/test")
	photoSchemaFile := filepath.Join(testDirectory, "photoSchema.json")
	photoBytes, err := os.ReadFile(photoSchemaFile)
	assert.NoError(t, err)
	validator, err := NewValidator(photoBytes, "PhotoApp")

	tests := []struct {
		name     string
		idql     string
		wantErrs []error
	}{
		{
			name: "Simple Photo",
			idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "User:alice"
  ],
 "actions": [ "Action:viewPhoto" ],
 "object": "Photo:VacationPhoto.jpg"
}`,
			wantErrs: nil,
		},
		{
			name: "Fully qualified",
			idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "PhotoApp:User:alice"
  ],
 "actions": [ "PhotoApp:Action:viewPhoto" ],
 "object": "PhotoApp:Photo:VacationPhoto.jpg"
}`,
			wantErrs: nil,
		},
		{
			name: "Any Test",
			idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "any"
  ],
 "actions": [ "Action:viewPhoto" ],
 "object": "Photo:VacationPhoto.jpg"
}`,
			wantErrs: nil,
		},
		{
			name: "Empty Action",
			idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "any"
  ],
 "actions": [  ],
 "object": "Photo:VacationPhoto.jpg"
}`,
			wantErrs: nil,
		},
		{
			name: "Bad subject type",
			idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "Admins:alice"
  ],
 "actions": [ "Action:viewPhoto" ],
 "object": "Photo:VacationPhoto.jpg"
}`,
			wantErrs: []error{
				errors.New(fmt.Sprintf("invalid subject entity type: %s:%s", "PhotoApp", "Admins")),
				errors.New(fmt.Sprintf("invalid principal type (%s:%s), must be one of %+q", "PhotoApp", "Admins", []string{"User", "UserGroup"})),
			},
		},
		{
			name: "Untyped object",
			idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "User:alice"
  ],
 "actions": [ "Action:viewPhoto" ],
 "object": "VacationPhoto.jpg"
}`,
			wantErrs: []error{
				errors.New(fmt.Sprintf("missing object entity type: %s:<type>:%s", "PhotoApp", "VacationPhoto.jpg")),
				errors.New(fmt.Sprintf("invalid object type (%s:%s), must be one of %+q", "PhotoApp", "", []string{"Photo"})),
			},
		},
		// The following test confirms that the use of the type "Action" isn't actually necessary. Note if action
		// Is to be referenced in another namespace, than the type is required (e.g. PhotoApp:Action:viewPhoto)
		{
			name: "Test that Action:<actionname> is optional",
			idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "User:alice"
  ],
 "actions": [ "viewPhoto" ],
 "object": "Photo:VacationPhoto.jpg"
}`,
			wantErrs: nil,
		},
		{
			name: "Test invalid namespace",
			idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "BadApp:User:alice"
  ],
 "actions": [ "Action:viewPhoto" ],
 "object": "BadApp:Photo:VacationPhoto.jpg"
}`,
			wantErrs: []error{
				errors.New(fmt.Sprintf("invalid subject PIM namespace (%s)", "BadApp")),
				errors.New(fmt.Sprintf("invalid object PIM namespace (%s)", "BadApp")),
				errors.New(fmt.Sprintf("invalid principal type (%s:%s), must be one of %+q", "BadApp", "User", []string{"User", "UserGroup"})),
				errors.New(fmt.Sprintf("invalid object type (%s:%s), must be one of %+q", "BadApp", "Photo", []string{"Photo"})),
			},
		},
		{
			name: "Invalid Action",
			idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "User:alice"
  ],
 "actions": [ "Action:badAction","BadNamespace:Action:invalid" ],
 "object": "Photo:VacationPhoto.jpg"
}`,
			wantErrs: []error{
				errors.New(fmt.Sprintf("invalid action type: %s:Action:%s", "PhotoApp", "badAction")),
				errors.New(fmt.Sprintf("invalid PIM namespace (%s)", "BadNamespace")),
			},
		},
		{
			name: "No object",
			idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "User:alice"
  ],
 "actions": [ "Action:viewPhoto" ],
 "object": ""
}`,
			wantErrs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var policy hexapolicy.PolicyInfo
			if err := json.Unmarshal([]byte(tt.idql), &policy); err != nil {
				assert.Fail(t, err.Error())
			}
			errs := validator.ValidatePolicy(policy)
			if tt.wantErrs == nil {
				if errs != nil {
					for _, err := range errs {
						fmt.Println(err.Error())
					}
				}
				assert.Nil(t, errs)
			} else {
				assert.Equal(t, len(tt.wantErrs), len(errs))
				assert.True(t, reflect.DeepEqual(tt.wantErrs, errs), "Errors should be the same")
			}
		})
	}
}

func TestPolicySet(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	testDirectory := filepath.Join(filepath.Dir(file), "../../../", "models/policyInfoModel/test")
	photoPolicyFile := filepath.Join(testDirectory, "cedarPhotoPolicy.txt")
	cedarBytes, err := os.ReadFile(photoPolicyFile)
	cedarMapper := cedar.NewCedarMapper(make(map[string]string))
	idql, err := cedarMapper.MapCedarPolicyBytes("cedarPhotoPolicy.txt", cedarBytes)
	assert.NoError(t, err)
	assert.NotNil(t, idql)

	photoSchemaFile := filepath.Join(testDirectory, "photoSchema.json")
	photoSchemaBytes, err := os.ReadFile(photoSchemaFile)
	assert.NoError(t, err)

	validator, err := NewValidator(photoSchemaBytes, "PhotoApp")
	assert.NoError(t, err)

	var report map[string][]error
	report = validator.ValidatePolicies(*idql)
	assert.Nil(t, report)

	idql.Policies[0].Subjects = hexapolicy.SubjectInfo{"Admins:alice"}

	report = validator.ValidatePolicies(*idql)
	assert.NotNil(t, report)
	perrs, ok := report["Policy-0"]
	assert.True(t, ok)
	assert.Equal(t, 2, len(perrs))
}
