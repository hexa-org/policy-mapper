package parser

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntityPath(t *testing.T) {
	idval := "gerry"
	idgroup := "admins"
	inEntity := EntityPath{Type: RelTypeEquals, Types: []string{"Group"}, Id: &idgroup}
	inEntity2 := EntityPath{Type: RelTypeEquals, Types: []string{"Employee"}, Id: &idgroup}
	inEntities := []EntityPath{inEntity}
	inEntitiesMulti := []EntityPath{inEntity, inEntity2}
	getPhoto := "getPhoto"
	tests := []struct {
		name     string
		input    string
		want     EntityPath
		wantType string
	}{
		{
			name:  "Any",
			input: "any",
			want: EntityPath{
				Type: RelTypeAny,
			},
			wantType: "",
		},
		{
			name:  "Authenticated",
			input: "anyAuthenticated",
			want: EntityPath{
				Type: RelTypeAnyAuthenticated,
			},
			wantType: "",
		},
		{
			name:  "Is User",
			input: "User:",
			want: EntityPath{
				Type:  RelTypeIs,
				Types: []string{"User"},
			},
			wantType: "User",
		},
		{
			name:  "User:gerry",
			input: "User:gerry",
			want: EntityPath{
				Type:  RelTypeEquals,
				Types: []string{"User"},
				Id:    &idval,
			},
			wantType: "User",
		},
		{
			name:  "Multi-entity type",
			input: "PhotoApp:Action:getPhoto",
			want: EntityPath{
				Type:  RelTypeEquals,
				Types: []string{"PhotoApp", "Action"},
				Id:    &getPhoto,
			},
			wantType: "Action",
		},
		{
			name:  "Is User in Group",
			input: "User[Group:admins]",
			want: EntityPath{
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
			want: EntityPath{
				Type: RelTypeIn,
				Id:   nil,
				In:   &inEntities,
			},
			wantType: "",
		},
		{
			name:  "In set of entities",
			input: "[Group:admins,Employee:admins]",
			want: EntityPath{
				Type: RelTypeIn,
				Id:   nil,
				In:   &inEntitiesMulti,
			},
			wantType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fmt.Println("Testing: " + tt.name)

			result := ParseEntityPath(tt.input)
			assert.NotNil(t, result)
			if !reflect.DeepEqual(*result, tt.want) {
			}

			// Test that the String() function is working
			assert.Equal(t, tt.input, result.String(), "String() should produce original input")

			assert.Equal(t, tt.wantType, result.GetType(), "Object type should match")
		})
	}
}
