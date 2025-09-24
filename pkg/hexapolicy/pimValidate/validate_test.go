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

func TestValidate_BadSchema(t *testing.T) {
	badBytes := []byte("{ unparsable}")

	validator, err := NewValidator(badBytes, "WrongApp")
	assert.Error(t, err)
	assert.Nil(t, validator)
}

func TestValidate_Policy(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	testDirectory := filepath.Join(filepath.Dir(file), "../../../", "models/policyInfoModel/test")
	photoSchemaFile := filepath.Join(testDirectory, "cmvSchemaTest.json")
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
				errors.New("invalid subject entity type: PhotoApp:Admins"),
				errors.New("policy cannot be applied to subject \"Admins:alice\", must be one of [\"User\" \"UserGroup\"]"),
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
				errors.New("missing object entity type: PhotoApp:<type>:VacationPhoto.jpg"),
				errors.New("policy cannot be applied to object type \"VacationPhoto.jpg\", must be one of [\"Photo\"]"),
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
				errors.New("invalid subject namespace \"BadApp\""),
				errors.New("invalid object namespace \"BadApp\""),
				errors.New("policy cannot be applied to subject \"BadApp:User:alice\", must be one of [\"User\" \"UserGroup\"]"),
				errors.New("policy cannot be applied to object type \"BadApp:Photo:VacationPhoto.jpg\", must be one of [\"Photo\"]"),
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
				errors.New(fmt.Sprintf("invalid action \"%s\"", "Action:badAction")),
				errors.New(fmt.Sprintf("invalid namespace \"%s\"", "BadNamespace")),
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
		{name: "Condition ", //here
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "Photo:VacationPhoto.jpg",
		  "condition": {
		    "rule": "PhotoApp:User:name pr and User:userId ew \"Emp\"",
		    "action": "allow"
		  }
		}`,
			wantErrs: nil,
		},
		{name: "Condition Parse Error",
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "Photo:VacationPhoto.jpg",
		  "condition": {
		    "rule": "PhotoApp:User:name and User:userId ew \"Emp\"",
		    "action": "allow"
		  }
		}`,
			wantErrs: []error{
				errors.New("invalid condition: Unsupported comparison operator: User:userId"),
			},
		},
		{name: "Condition Bad Type",
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "Photo:VacationPhoto.jpg",
		  "condition": {
		    "rule": "User:userId gt 1234",
		    "action": "allow"
		  }
		}`,
			wantErrs: []error{
				errors.New("expression \"User:userId gt 1234\" has mis-matched attribute types: String and Long"),
			},
		},
		{name: "Bad Condition Namespace",
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "Photo:VacationPhoto.jpg",
		  "condition": {
		    "rule": "Todo:User:userId gt \"a\"",
		    "action": "allow"
		  }
		}`,
			wantErrs: []error{
				errors.New("invalid namespace \"Todo\" for Todo:User:userId"),
			},
		},
		{name: "Bad Condition Entity",
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "Photo:VacationPhoto.jpg",
		  "condition": {
		    "rule": "BadUser:userId gt \"a\"",
		    "action": "allow"
		  }
		}`,
			wantErrs: []error{
				errors.New("invalid condition entity type: BadUser:userId"),
			},
		},
		{name: "Undefined attribute",
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "Photo:VacationPhoto.jpg",
		  "condition": {
		    "rule": "User:badAttr gt \"a\"",
		    "action": "allow"
		  }
		}`,
			wantErrs: []error{
				errors.New("invalid condition attribute: User:badAttr"),
			},
		},
		{name: "Date and bool",
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "Photo:VacationPhoto.jpg",
		  "condition": {
		    "rule": "User:lastReviewed gt 1985-04-12T23:20:50.52Z and User:isEmployee eq true",
		    "action": "allow"
		  }
		}`,
			wantErrs: nil,
		},
		{name: "Quoted Date",
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "Photo:VacationPhoto.jpg",
		  "condition": {
		    "rule": "User:lastReviewed gt \"1985-04-12T23:20:50.52Z\"",
		    "action": "allow"
		  }
		}`,
			wantErrs: []error{
				errors.New("expression \"User:lastReviewed gt \"1985-04-12T23:20:50.52Z\"\" has mis-matched attribute types: Date and String"),
			},
		},
		{name: "SW-EW non-string",
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "Photo:VacationPhoto.jpg",
		  "condition": {
		    "rule": "User:lastReviewed sw \"1985\" and User:userId ew 123",
		    "action": "allow"
		  }
		}`,
			wantErrs: []error{
				errors.New("expression \"User:lastReviewed sw \"1985\"\" requires String comparators (User:lastReviewed is Date)"),
				errors.New("expression \"User:userId ew 123\" requires String comparators (123 is Long)"),
			},
		},
		{name: "IN-CO non-string",
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "Photo:VacationPhoto.jpg",
		  "condition": {
		    "rule": "User:lastReviewed in UserGroup:\"abc\" and UserGroup:\"admins\" co 123",
		    "action": "allow"
		  }
		}`,
			wantErrs: []error{
				errors.New("expression \"User:lastReviewed in UserGroup:\"abc\"\" requires an Entity or String comparator (User:lastReviewed is Date)"),
				errors.New("expression \"UserGroup:\"admins\" co 123\" requires an Entity or String comparator (123 is Long)"),
			},
		},
		{name: "ValuePath",
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "Photo:VacationPhoto.jpg",
		  "condition": {
		    "rule": "User:emails[type eq \"work\"].value ew \"@example.com\"",
		    "action": "allow"
		  }
		}`,
			wantErrs: []error{
				errors.New("valuePath expressions \"User:emails[type eq \"work\"].value ew \"@example.com\"\" are not supported"),
			},
		},
		{name: "Invalid Object Type",
			idql: `{
		  "meta": {
		    "version": "0.7"
		  },
		  "subjects": [
		    "User:alice"
		  ],
		  "actions": [
		    "Action:viewPhoto"
		  ],
		  "object": "BadPhoto:VacationPhoto.jpg"
		}`,
			wantErrs: []error{
				errors.New("invalid object entity type: PhotoApp:BadPhoto"),
				errors.New("policy cannot be applied to object type \"BadPhoto:VacationPhoto.jpg\", must be one of [\"Photo\"]"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var policy hexapolicy.PolicyInfo
			if err := json.Unmarshal([]byte(tt.idql), &policy); err != nil {
				assert.Fail(t, err.Error())
			}
			assert.NotNil(t, policy, "Check test policy was parsed")
			assert.NotNil(t, policy.Subjects, "Test policy should have subjects if valid")
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

	testId := "TestPolicy0"
	idql.Policies[0].Meta.PolicyId = &testId

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
	perrs, ok := report["Policy-"+testId]
	assert.True(t, ok)
	assert.Equal(t, 2, len(perrs))
}

func TestTodoPolicy(t *testing.T) {

	_, file, _, _ := runtime.Caller(0)
	testDirectory := filepath.Join(filepath.Dir(file), "../../../", "models/policyInfoModel/test")
	schemaFile := filepath.Join(testDirectory, "todoSchema.json")
	schemaBytes, err := os.ReadFile(schemaFile)
	assert.NoError(t, err)
	validator, err := NewValidator(schemaBytes, "TodoApp")

	tests := []struct {
		name     string
		idql     string
		wantErrs []error
	}{
		{
			name: "GetUsers",
			idql: `{
		  "meta": {
		    "policyId": "GetUsers",
		    "version": "0.7",
		    "description": "Get information associated with a user"
		  },
		  "subjects": [
		    "anyAuthenticated"
		  ],
		  "actions": [
		    "can_read_user"
		  ],
		  "object": "user:"
		}`,
			wantErrs: nil,
		},
		{
			name: "GetTodos",
			idql: `{
		  "meta": {
		    "policyId": "GetTodos",
		    "version": "0.7",
		    "description": "Get the list of todos. Always returns true for every user??"
		  },
		  "subjects": [
		    "anyAuthenticated"
		  ],
		  "actions": [
		    "can_read_todos"
		  ],
		  "object": "todo:"
		}`,
			wantErrs: nil,
		},
		{
			name: "CreateTodo",
			idql: `    {
		  "meta": {
		    "version": "0.7",
		    "description": "Create a new Todo",
		    "policyId": "PostTodo"
		  },
		  "subjects": [
		    "role:admin",
		    "role:editor"
		  ],
		  "actions": [
		    "can_create_todo"
		  ],
		  "object": "todo:"
		}`,
			wantErrs: nil,
		},
		{
			name: "PutTodo",
			idql: `{
		  "meta": {
		    "version": "0.7",
		    "description": "Un(complete) a todo.",
		    "policyId": "PutTodo"
		  },
		  "subjects": [
		    "anyAuthenticated"
		  ],
		  "actions": [
		    "can_update_todo"
		  ],
		  "condition": {
		    "rule": "subject.roles co \"evil_genius\" or (subject.roles co \"editor\" and resource.properties.ownerID eq subject.claims.email)",
		    "action": "allow"
		  },
		  "object": "todo:"
		}`,
			wantErrs: nil,
		},
		{
			name: "DeleteTodo",
			idql: `{
		  "meta": {
		    "version": "0.7",
		    "description": "Delete a todo if admin or owner of todo",
		    "policyId": "DeleteTodo"
		  },
		  "subjects": [
		    "anyAuthenticated"
		  ],
		  "actions": [
		    "can_delete_todo"
		  ],
		  "condition": {
		    "rule": "subject.roles co \"admin\" or (subject.roles co \"editor\" and resource.properties.ownerID eq subject.claims.email)",
		    "action": "allow"
		  },
		  "object": "todo:"
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
			assert.NotNil(t, policy, "Check test policy was parsed")
			assert.NotNil(t, policy.Subjects, "Test policy should have subjects if valid")
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
