// Package parser is used to parse values that represent entities that are contained within IDQL
// `PolicyInfo` for `SubjectInfo`, `ActionInfo`, and `Object`. This package will
// be used by the schema validator to evaluate whether an IDQL policy conforms to policy.
package types

import (
	"fmt"
	"strings"
)

const (
	RelTypeAny              = "any"              // Used for allowing any subject including anonymous
	RelTypeAnyAuthenticated = "anyAuthenticated" // Used for allowing any subject that was authenticated
	RelTypeIs               = "is"               // Matching by type such as `User:`
	RelTypeIsIn             = "isIn"             // Type is in set such as `User[Group:admins]`
	RelTypeIn               = "in"               // Matching through membership in a set or entity [Group:admins]
	RelTypeEquals           = "eq"
	RelTypeEmpty            = "nil" // Matches a specific type and identifier e.g. `User:alice@example.co`
)

// Entity represents a path that points to an entity used in IDQL policy (Subjects, Actions, Object).
type Entity struct {
	Types []string  // Types is the parsed entity structure e.g. PhotoApp:Photo
	Type  string    // The type of relationship being expressed (see RelTypeEquals, ...)
	Id    *string   // The id of a specific entity instance within type. (e.g. myvactionphoto.jpg)
	In    *[]Entity // When an entity represents a set of entities (e.g. [PhotoApp:Photo:picture1.jpg,PhotoApp:Photo:picture2.jpg])
	//  *string
}

func (e Entity) OperandType() int {
	return RelTypeVariable
}

// ParseEntity takes a string value from an IDQL Subject, Action, or Object parses
// it into an Entity struct.
func ParseEntity(value string) *Entity {
	if value == "" {
		return &Entity{
			Type: RelTypeEmpty,
		}
	}

	var typePath []string
	var sets []Entity
	var id *string

	sb := strings.Builder{}
	setb := strings.Builder{}
	isSet := false
	for _, r := range value {
		if r == ':' && !isSet {
			// found entity separator
			typePath = append(typePath, sb.String())
			sb.Reset()
			continue
		}
		if r == '[' {
			// found set
			isSet = true
			if sb.Len() > 0 {
				// save any parsed type before parsing set
				typePath = append(typePath, sb.String())
				sb.Reset()
			}
			continue
		}
		if r == ']' {
			isSet = false
			setString := setb.String()
			inset := strings.Split(setString, ",")
			for _, member := range inset {
				entitypath := ParseEntity(member)
				if entitypath != nil {
					sets = append(sets, *entitypath)
				}
			}
			setb.Reset()
			continue
		}

		if isSet {
			setb.WriteRune(r)
		} else {
			sb.WriteRune(r)
		}
	}
	if sb.Len() > 0 {
		idValue := sb.String()
		id = &idValue
	}

	if id != nil {
		if strings.EqualFold(*id, "any") {
			return &Entity{
				Types: nil,
				Type:  RelTypeAny,
			}
		}
		if strings.EqualFold(*id, "anyauthenticated") {
			return &Entity{
				Types: nil,
				Type:  RelTypeAnyAuthenticated,
			}
		}
	}

	if sets != nil && len(sets) > 0 {
		// This is an in or is in
		if typePath == nil || len(typePath) == 0 {
			// this is an in
			return &Entity{
				Types: nil,
				Type:  RelTypeIn,
				In:    &sets,
			}
		}
		return &Entity{
			Type:  RelTypeIsIn,
			Types: typePath,
			In:    &sets,
		}
	}

	// This is an is (e.g. User:)
	if id == nil {
		return &Entity{
			Type:  RelTypeIs,
			Types: typePath,
		}
	}

	// This is just a straight equals (e.g. User:alice)
	return &Entity{
		Type:  RelTypeEquals,
		Types: typePath,
		Id:    id,
	}
}

func (e Entity) String() string {
	switch e.Type {
	case RelTypeAny:
		return "any"
	case RelTypeAnyAuthenticated:
		return "anyAuthenticated"
	case RelTypeEquals:
		if e.Types == nil {
			return *e.Id
		}
		return fmt.Sprintf("%s:%s", strings.Join(e.Types, ":"), *e.Id)
	case RelTypeIs:
		return fmt.Sprintf("%s:", strings.Join(e.Types, ":"))
	case RelTypeIsIn:
		sb := strings.Builder{}
		for i, entity := range *e.In {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(entity.String())
		}
		return fmt.Sprintf("%s[%s]", strings.Join(e.Types, ":"), sb.String())
	case RelTypeIn:
		sb := strings.Builder{}
		for i, entity := range *e.In {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(entity.String())
		}
		return fmt.Sprintf("[%s]", sb.String())
	case RelTypeEmpty:
		return ""
	}
	return "unexpected type: " + e.Type
}

func (e Entity) Value() interface{} {
	return e.String()
}

// GetType returns the immediate parent type. For example:  for PhotoApp:User:smith, the type is User
// If no parent is defined an empty string "" is returned
func (e Entity) GetType() string {
	if e.Type == RelTypeAny {
		return RelTypeAny
	}
	if e.Type == RelTypeAnyAuthenticated {
		return RelTypeAnyAuthenticated
	}
	if len(e.Types) == 0 {
		return ""
	}
	if e.Types == nil {
		return ""
	}
	return e.Types[len(e.Types)-1]
}

// GetNamespace returns the entity's namespace if it is defined, otherwise returns defaultNamespace.
// For example, for PhotoApp:Photo:vacation.jpg would return PhotoApp. Photo:vacation.jpg would return the value of defaultNamespace.
func (e Entity) GetNamespace(defaultNamespace string) string {
	if len(e.Types) > 1 {
		return e.Types[0]
	}
	return defaultNamespace
}
