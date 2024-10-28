// Package pim (application Policy Information Model) is used by Hexa tools to validate that a policy is valid for a particular
// application.  The model is based on [Cedar Schema](https://docs.cedarpolicy.com/schema/schema.html).
package policyInfoModel

import (
	"encoding/json"
	"strings"

	hexaTypes "github.com/hexa-org/policy-mapper/pkg/hexapolicy/types"
)

const (
	TypePerson    string = "PersonType"
	TypeRecord    string = "Record"
	TypeSet       string = "Set"
	TypeBool      string = "Bool"
	TypeString    string = "String"
	TypeDate      string = "Date"
	TypeNumeric   string = "Numeric"
	TypeLong      string = "Long"
	TypeExtension string = "Extension"
)

type hasAttributes interface {
	FindAttrTypes(path string, schema SchemaType) *AttrType
}

type SetType struct {
	Element *AttrType `json:"element"`
}

type AttrType struct {
	Type     string `json:"type"`
	Name     string `json:"name,omitempty"`
	Required bool   `json:"required"`
	SetType
	RecordType
}

type RecordType struct {
	Attributes map[string]AttrType `json:"attributes"`
}

func (h AttrType) FindAttrTypes(path string, schema SchemaType) *AttrType {
	comps := strings.SplitN(path, ".", 2)
	if h.SetType.Element != nil {
		sType, ok := h.SetType.Element.Attributes[comps[0]]
		if ok {
			if len(comps) == 1 {
				return &sType
			}
			return sType.FindAttrTypes(comps[1], schema)
		}
	}

	if h.RecordType.Attributes != nil {
		return doFindAttr(h.RecordType.Attributes, path, schema)
	}
	return nil
}

type ContextType struct {
	Type       string              `json:"type"` // fixed as "RecordType"
	Attributes map[string]AttrType `json:"attributes"`
}

func (c ContextType) FindAttrTypes(path string, schema SchemaType) *AttrType {
	return doFindAttr(c.Attributes, path, schema)
}

type ResourceTypes []string
type PrincipalTypes []string

type AppliesType struct {
	PrincipalTypes *PrincipalTypes `json:"principalTypes,omitempty"`
	ResourceTypes  *ResourceTypes  `json:"resourceTypes,omitempty"`
	Context        *ContextType    `json:"context,omitempty"`
}

// Action ::= STR ':' '{' [ '"memberOf"' ':' '[' [ STR { ',' STR } ] ']' ] ',' [ '"appliesTo"' ':' '{' [PrincipalTypes] ',' [ResourceTypes] ',' [Context] '}' ] '}'
type ActionType struct {
	MemberOf  []string    `json:"memberOf,omitempty"`
	AppliesTo AppliesType `json:"appliesTo,omitempty"`
}

type ShapeTypes struct {
	Type       string              `json:"type"`
	Attributes map[string]AttrType `json:"attributes"`
}

func (s ShapeTypes) FindAttrType(path string, schema SchemaType) *AttrType {
	return doFindAttr(s.Attributes, path, schema)
}

func doFindAttr(attributes map[string]AttrType, path string, schema SchemaType) *AttrType {
	if path == "" || attributes == nil {
		return nil
	}
	comps := strings.SplitN(path, ".", 2)
	for name, attrType := range attributes {
		if strings.EqualFold(comps[0], name) {
			if len(comps) == 1 {
				return &attrType
			}
			subAttr := attrType.FindAttrTypes(comps[1], schema)
			if subAttr != nil {
				return subAttr
			}
		}
		switch attrType.Type {
		case TypeString, TypeBool, TypeDate, TypeNumeric, TypeLong, TypeExtension, TypeRecord, TypeSet:
			continue
		default:
			// This is a custom type - lookup under "commonTypes"
			cType, ok := schema.CommonTypes[attrType.Type]
			if ok {
				attr := cType.FindAttrTypes(path, schema)
				if attr != nil {
					return attr
				}
			}
		}

	}
	return nil
}

// EntityType ::= IDENT ':' '{' [ 'memberOfTypes' ':' '[' [ IDENT { ',' IDENT } ] ']' ] ',' [ 'shape': TypeJson ] '}'
type EntityType struct {
	MemberOfTypes []string   `json:"memberOfTypes,omitempty"`
	Shape         ShapeTypes `json:"shape,omitempty"`
}

func (e EntityType) FindAttrType(path string, schema SchemaType) *AttrType {
	return e.Shape.FindAttrType(path, schema)
}

type SchemaType struct {
	EntityTypes map[string]EntityType  `json:"entityTypes,omitempty"`
	Actions     map[string]ActionType  `json:"actions,omitempty"`
	CommonTypes map[string]ContextType `json:"commonTypes,omitempty"`
}

// FindAttrType locates an AttrType definition by using the path format:  <entityType>:<attr>.<subAttribute>
func (s SchemaType) FindAttrType(entity hexaTypes.Entity) *AttrType {
	eType, ok := s.EntityTypes[entity.GetType()]
	if ok {
		if entity.IsPath() {
			return eType.FindAttrType(entity.GetId(), s)
		}
	}
	return nil
}

type Namespaces map[string]SchemaType

func ParseSchemaFile(schemaBytes []byte) (*Namespaces, error) {

	var namespaces Namespaces
	err := json.Unmarshal(schemaBytes, &namespaces)
	return &namespaces, err
}
