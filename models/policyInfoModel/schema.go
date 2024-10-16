// Package pim (application Policy Information Model) is used by Hexa tools to validate that a policy is valid for a particular
// application.  The model is based on [Cedar Schema](https://docs.cedarpolicy.com/schema/schema.html).
package policyInfoModel

import "encoding/json"

type LongType struct {
	Type string `json:"type"` // is "Long"
}

type SetType struct {
	Type    string        `json:"type"` // is "Set"
	Element []interface{} `json:"element"`
}

type AttrType struct {
	Type     string `json:"type"`
	Name     string `json:"name,omitempty"`
	Required bool   `json:"required"`
}

type RecordType struct {
	Type       string              `json:"type"` // fixed as "RecordType"
	Attributes map[string]AttrType `json:"attributes"`
}

type ContextType struct {
	Type       string              `json:"type"` // fixed as "RecordType"
	Attributes map[string]AttrType `json:"attributes"`
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

// EntityType ::= IDENT ':' '{' [ 'memberOfTypes' ':' '[' [ IDENT { ',' IDENT } ] ']' ] ',' [ 'shape': TypeJson ] '}'
type EntityType struct {
	MemberOfTypes []string   `json:"memberOfTypes,omitempty"`
	Shape         ShapeTypes `json:"shape,omitempty"`
}

type SchemaType struct {
	EntityTypes map[string]EntityType  `json:"entityTypes,omitempty"`
	Actions     map[string]ActionType  `json:"actions,omitempty"`
	CommonTypes map[string]ContextType `json:"commonTypes,omitempty"`
}

type Namespaces map[string]SchemaType

func ParseSchemaFile(schemaBytes []byte) (*Namespaces, error) {

	var namespaces Namespaces
	err := json.Unmarshal(schemaBytes, &namespaces)
	return &namespaces, err
}
