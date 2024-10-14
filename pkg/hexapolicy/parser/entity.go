// Package parser is used to parse values that represent entities that are contained within IDQL
// `PolicyInfo` for `SubjectInfo`, `ActionInfo`, and `Object`. This package will
// be used by the schema validator to evaluate whether an IDQL policy conforms to policy.
package parser

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
	RelTypeEquals           = "eq"               // Matches a specific type and identifier e.g. `User:alice@example.co`
)

// EntityPath represents a path that points to an entity used in IDQL policy (Subjects, Actions, Object).
type EntityPath struct {
	Types []string      // Types is the parsed entity structure e.g. PhotoApp:Photo
	Type  string        // The type of relationship being expressed (see RelTypeEquals, ...)
	Id    *string       // The id of a specific entity instance within type. (e.g. myvactionphoto.jpg)
	In    *[]EntityPath // When an entity represents a set of entities (e.g. [PhotoApp:Photo:picture1.jpg,PhotoApp:Photo:picture2.jpg])
	//  *string
}

// ParseEntityPath takes a string value from an IDQL Subject, Action, or Object parses
// it into an EntityPath struct.
func ParseEntityPath(value string) *EntityPath {
	var typePath []string
	var sets []EntityPath
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
				entitypath := ParseEntityPath(member)
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
			return &EntityPath{
				Types: nil,
				Type:  RelTypeAny,
			}
		}
		if strings.EqualFold(*id, "anyauthenticated") {
			return &EntityPath{
				Types: nil,
				Type:  RelTypeAnyAuthenticated,
			}
		}
	}

	if sets != nil && len(sets) > 0 {
		// This is an in or is in
		if typePath == nil || len(typePath) == 0 {
			// this is an in
			return &EntityPath{
				Types: nil,
				Type:  RelTypeIn,
				In:    &sets,
			}
		}
		return &EntityPath{
			Type:  RelTypeIsIn,
			Types: typePath,
			In:    &sets,
		}
	}

	// This is an is (e.g. User:)
	if id == nil {
		return &EntityPath{
			Type:  RelTypeIs,
			Types: typePath,
		}
	}

	// This is just a straight equals (e.g. User:alice)
	return &EntityPath{
		Type:  RelTypeEquals,
		Types: typePath,
		Id:    id,
	}
}

func (e *EntityPath) String() string {
	switch e.Type {
	case RelTypeAny:
		return "any"
	case RelTypeAnyAuthenticated:
		return "anyAuthenticated"
	case RelTypeEquals:
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
	}
	return "unexpected type: " + e.Type
}

// GetType returns the immediate parent type. For exmaple:  for PhotoApp:User:smith, the type is User
// If no parent is defined an empty string "" is returned
func (e *EntityPath) GetType() string {
	if len(e.Types) == 0 {
		return ""
	}
	return e.Types[len(e.Types)-1]
}
