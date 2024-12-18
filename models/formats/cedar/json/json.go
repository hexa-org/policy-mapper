// Package json Note: This code is from github.com/cedar-policy/cedar-go and is used under the APL 2.0 license terms.
package json

import (
	"encoding/json"

	"github.com/cedar-policy/cedar-go/types"
)

type PolicyJSON struct {
	Annotations map[string]string `json:"annotations,omitempty"`
	Effect      string            `json:"effect"`
	Principal   ScopeJSON         `json:"principal"`
	Action      ScopeJSON         `json:"action"`
	Resource    ScopeJSON         `json:"resource"`
	Conditions  []ConditionJSON   `json:"conditions,omitempty"`
}

// scopeInJSON uses the implicit form of EntityUID JSON serialization to match the Rust SDK
type scopeInJSON struct {
	Entity types.ImplicitlyMarshaledEntityUID `json:"entity"`
}

// ScopeJSON uses the implicit form of EntityUID JSON serialization to match the Rust SDK
type ScopeJSON struct {
	Op         string                               `json:"op"`
	Entity     *types.ImplicitlyMarshaledEntityUID  `json:"entity,omitempty"`
	Entities   []types.ImplicitlyMarshaledEntityUID `json:"entities,omitempty"`
	EntityType string                               `json:"entity_type,omitempty"`
	In         *scopeInJSON                         `json:"in,omitempty"`
}

type ConditionJSON struct {
	Kind string   `json:"kind"`
	Body NodeJSON `json:"body"`
}

type BinaryJSON struct {
	Left  NodeJSON `json:"left"`
	Right NodeJSON `json:"right"`
}

type unaryJSON struct {
	Arg NodeJSON `json:"arg"`
}

type strJSON struct {
	Left NodeJSON `json:"left"`
	Attr string   `json:"attr"`
}

type likeJSON struct {
	Left    NodeJSON      `json:"left"`
	Pattern types.Pattern `json:"pattern"`
}

type isJSON struct {
	Left       NodeJSON  `json:"left"`
	EntityType string    `json:"entity_type"`
	In         *NodeJSON `json:"in,omitempty"`
}

type ifThenElseJSON struct {
	If   NodeJSON `json:"if"`
	Then NodeJSON `json:"then"`
	Else NodeJSON `json:"else"`
}

type arrayJSON []NodeJSON

type recordJSON map[string]NodeJSON

type extensionJSON map[string]arrayJSON

type ValueJSON struct {
	V types.Value
}

func (e *ValueJSON) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.V)
}

func (e *ValueJSON) UnmarshalJSON(b []byte) error {
	return types.UnmarshalJSON(b, &e.V)
}

type NodeJSON struct {
	// Value
	Value *ValueJSON `json:"Value,omitempty"` // could be any

	// Var
	Var *string `json:"Var,omitempty"`

	// Slot
	// Unknown

	// ! or neg operators
	Not    *unaryJSON `json:"!,omitempty"`
	Negate *unaryJSON `json:"neg,omitempty"`

	// Binary operators: ==, !=, in, <, <=, >, >=, &&, ||, +, -, *, contains, containsAll, containsAny
	Equals                 *BinaryJSON `json:"==,omitempty"`
	NotEquals              *BinaryJSON `json:"!=,omitempty"`
	In                     *BinaryJSON `json:"in,omitempty"`
	LessThan               *BinaryJSON `json:"<,omitempty"`
	FuncLessThan           []NodeJSON  `json:"lessThan,omitempty"`
	LessThanOrEqual        *BinaryJSON `json:"<=,omitempty"`
	FuncLessThanOrEqual    []NodeJSON  `json:"lessThanOrEqual,omitempty"`
	GreaterThan            *BinaryJSON `json:">,omitempty"`
	FuncGreaterThan        []NodeJSON  `json:"greaterThan,omitempty"`
	GreaterThanOrEqual     *BinaryJSON `json:">=,omitempty"`
	FuncGreaterThanOrEqual []NodeJSON  `json:"greaterThanOrEqual,omitempty"`
	And                    *BinaryJSON `json:"&&,omitempty"`
	Or                     *BinaryJSON `json:"||,omitempty"`
	Add                    *BinaryJSON `json:"+,omitempty"`
	Subtract               *BinaryJSON `json:"-,omitempty"`
	Multiply               *BinaryJSON `json:"*,omitempty"`
	Contains               *BinaryJSON `json:"contains,omitempty"`
	ContainsAll            *BinaryJSON `json:"containsAll,omitempty"`
	ContainsAny            *BinaryJSON `json:"containsAny,omitempty"`
	GetTag                 *BinaryJSON `json:"getTag,omitempty"`
	HasTag                 *BinaryJSON `json:"hasTag,omitempty"`

	// ., has
	Access *strJSON `json:".,omitempty"`
	Has    *strJSON `json:"has,omitempty"`

	// is
	Is *isJSON `json:"is,omitempty"`

	// like
	Like *likeJSON `json:"like,omitempty"`

	// if-then-else
	IfThenElse *ifThenElseJSON `json:"if-then-else,omitempty"`

	// Set
	Set arrayJSON `json:"Set,omitempty"`

	// Record
	Record recordJSON `json:"Record,omitempty"`

	// Any other method: decimal, datetime, duration, ip, lessThan, lessThanOrEqual, greaterThan, greaterThanOrEqual, isIpv4, isIpv6, isLoopback, isMulticast, isInRange, toDate, toTime, toDays, toHours, toMinutes, toSeconds, toMilliseconds, offset, durationSince
	ExtensionCall extensionJSON `json:"-"`
}
