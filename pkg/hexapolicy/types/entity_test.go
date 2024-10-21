package types

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntityPath(t *testing.T) {
	idval := "gerry"
	idgroup := "admins"
	attrName := "username"
	inEntity := Entity{Type: RelTypeEquals, Types: []string{"Group"}, Id: &idgroup}
	inEntity2 := Entity{Type: RelTypeEquals, Types: []string{"Employee"}, Id: &idgroup}
	inEntities := []Entity{inEntity}
	inEntitiesMulti := []Entity{inEntity, inEntity2}
	getPhoto := "getPhoto"
	tests := []struct {
		name     string
		input    string
		want     Entity
		wantType string
	}{
		{
			name:  "Any",
			input: "any",
			want: Entity{
				Type: RelTypeAny,
			},
			wantType: RelTypeAny,
		},
		{
			name:  "Authenticated",
			input: "anyAuthenticated",
			want: Entity{
				Type: RelTypeAnyAuthenticated,
			},
			wantType: RelTypeAnyAuthenticated,
		},
		{
			name:  "Is User",
			input: "User:",
			want: Entity{
				Type:  RelTypeIs,
				Types: []string{"User"},
			},
			wantType: "User",
		},
		{
			name:  "User:gerry",
			input: "User:gerry",
			want: Entity{
				Type:  RelTypeEquals,
				Types: []string{"User"},
				Id:    &idval,
			},
			wantType: "User",
		},
		{
			name:  "Multi-entity type",
			input: "PhotoApp:Action:getPhoto",
			want: Entity{
				Type:  RelTypeEquals,
				Types: []string{"PhotoApp", "Action"},
				Id:    &getPhoto,
			},
			wantType: "Action",
		},
		{
			name:  "Is User in Group",
			input: "User[Group:admins]",
			want: Entity{
				Type:  RelTypeIsIn,
				Types: []string{"User"},
				Id:    nil,
				In:    &inEntities,
			},
			wantType: "User",
		},
		{
			name:  "In Group",
			input: "[Group:admins]",
			want: Entity{
				Type: RelTypeIn,
				Id:   nil,
				In:   &inEntities,
			},
			wantType: "",
		},
		{
			name:  "In set of entities",
			input: "[Group:admins,Employee:admins]",
			want: Entity{
				Type: RelTypeIn,
				Id:   nil,
				In:   &inEntitiesMulti,
			},
			wantType: "",
		},
		{
			name:  "Empty",
			input: "",
			want: Entity{
				Type: RelTypeEmpty,
			},
			wantType: "",
		},
		{
			name:  "Simple name",
			input: "username",
			want: Entity{
				Type: RelTypeEquals,
				Id:   &attrName,
			},
			wantType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("Testing: " + tt.name)

			result := ParseEntity(tt.input)
			assert.NotNil(t, result)
			if !reflect.DeepEqual(result, tt.want) {
			}

			// Test that the String() function is working
			assert.Equal(t, tt.input, result.String(), "String() should produce original input")

			assert.Equal(t, tt.wantType, result.GetType(), "Object type should match")
		})
	}
}
