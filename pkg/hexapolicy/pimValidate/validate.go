package pimValidate

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/hexa-org/policy-mapper/models/policyInfoModel"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/ast"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions/parser"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/types"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
)

type ValidationError struct {
	PolIndex    int
	ValIndex    int
	Start       ast.Position
	End         ast.Position
	ElementName string
	Value       string
	Errs        []error
}

func (e *ValidationError) Errors() []error {
	return e.Errs
}

func (e *ValidationError) String() string {
	resp := fmt.Sprintf("%15s [%d:%d] %s", e.ElementName, e.Start.Line, e.Start.Column, e.Value)
	for _, err := range e.Errs {
		resp += "\n" + err.Error()
	}
	return resp
}

type Validator struct {
	namespaces   policyInfoModel.Namespaces
	defNamespace string
}

func GetValidator(namespaces policyInfoModel.Namespaces, defNamespace string) *Validator {
	return &Validator{
		namespaces:   namespaces,
		defNamespace: defNamespace,
	}
}

func NewValidator(pimBytes []byte, defaultNamespace string) (*Validator, error) {
	namespaces, err := policyInfoModel.ParseSchemaFile(pimBytes)
	if err != nil {
		return nil, err
	}
	if namespaces == nil {
		return nil, errors.New("invalid PIM schema file")
	}
	return &Validator{namespaces: *namespaces, defNamespace: defaultNamespace}, nil
}

// ValidatePolicy checks `policy` (PolicyInfo) against the loaded Policy Information Model,
// `index` is the 0-based index of the policy within a set of policies. Index is used in ValidationError for positional
// indication in editors.
// When provided, appNamespace is used to default the main namespace for entities referenced the policy.
// For example
// if appNamespace is `PhotoApp`, an entity of `Photo:myphoto.jpg` will be located under `PhotoApp`
// If appNamespace is not provided, then each EntityPaths must contain the namespace as part of the type
// (e.g. PhotoApp:Photo:myphoto.jpg)
func (v *Validator) ValidatePolicy(policy hexapolicy.PolicyInfo, index int) []ValidationError {
	var errs []ValidationError

	tErrs := v.checkSubject(policy.Subjects, index)
	if tErrs != nil {
		errs = append(errs, tErrs...)
	}

	vErr := v.checkObject(policy.Object, index)
	if vErr != nil {
		errs = append(errs, *vErr)
	}

	tErrs = v.checkAction(policy, index)
	if tErrs != nil {
		errs = append(errs, tErrs...)
	}

	tErrs = v.checkConditions(policy, index)
	if tErrs != nil {
		errs = append(errs, tErrs...)
	}

	return errs
}

// ValidatePolicies validates a set of policies and returns a map whose index is as string containing either
// the policyId of a policy with errors or an index number of the policies original index in Policies
func (v *Validator) ValidatePolicies(policies hexapolicy.Policies) []ValidationError {
	var res []ValidationError

	for i, policy := range policies.Policies {
		errs := v.ValidatePolicy(policy, i)
		if errs != nil {
			res = append(res, errs...)
		}
	}
	return res
}

// ValidatePolicyByAst validates policies provided as raw JSON bytes and populates
// ValidationError Start/End positions using the AST of the original document.
// It produces similar output to ValidatePolicies but includes positional info
// for the element that caused the error.
func (v *Validator) ValidatePolicyByAst(policyBytes []byte) []ValidationError {
	// Parse both the policies and the AST of the same bytes
	pols, err := hexapolicysupport.ParsePolicies(policyBytes)
	if err != nil {
		// On parse error we cannot proceed with validation; return a single error without positions
		return []ValidationError{{
			PolIndex:    0,
			ValIndex:    0,
			ElementName: "document",
			Value:       "",
			Errs:        []error{err},
		}}
	}
	doc, _ := ast.ParseAST(policyBytes)

	var result []ValidationError
	for i, policy := range pols {
		errs := v.ValidatePolicy(policy, i)
		if len(errs) == 0 {
			continue
		}
		// Determine the AST policy node for this index, if available
		var pnode *ast.PolicyNode
		if doc != nil && i < len(doc.Policies) {
			pnode = doc.Policies[i]
		}
		// decorate each error with positions
		for _, e := range errs {
			if pnode == nil {
				result = append(result, e)
				continue
			}
			// choose field by element name
			var f *ast.FieldNode
			elemName := strings.ToLower(e.ElementName)
			switch elemName {
			case "subjects":
				f = pnode.Subjects
			case "actions":
				f = pnode.Actions
			case "object":
				f = pnode.Object
			case "condition", "condition-action":
				f = pnode.Condition
			default:
				// leave nil to fall back to policy span
			}
			if f != nil && f.Value != nil {
				// Prefer precise positioning when arrays/objects expose children
				switch elemName {
				case "subjects", "actions":
					// For arrays (subjects/actions), if ValIndex matches an element, use that element span
					if f.Value.Kind == "array" && e.ValIndex >= 0 && e.ValIndex < len(f.Value.Elements) {
						el := f.Value.Elements[e.ValIndex]
						e.Start = el.Pos()
						e.End = el.End()
						break
					}
					// fallback to entire value span
					e.Start = f.Value.Pos()
					e.End = f.Value.End()
				case "condition-action":
					// Try to locate the specific 'action' field inside condition object
					if pnode.ConditionAction() != nil && pnode.ConditionAction().Value != nil {
						e.Start = pnode.ConditionAction().Value.Pos()
						e.End = pnode.ConditionAction().Value.End()
						break
					}
					// fallback to condition value span
					e.Start = f.Value.Pos()
					e.End = f.Value.End()
				case "condition":
					// Prefer the specific rule field when available
					if pnode.ConditionRule() != nil && pnode.ConditionRule().Value != nil {
						e.Start = pnode.ConditionRule().Value.Pos()
						e.End = pnode.ConditionRule().Value.End()
						break
					}
					// fallback to condition value span
					e.Start = f.Value.Pos()
					e.End = f.Value.End()
				default:
					// object generic: use the field value span
					e.Start = f.Value.Pos()
					e.End = f.Value.End()
				}
			} else {
				// fallback to the whole policy span
				e.Start = pnode.Pos()
				e.End = pnode.End()
			}
			result = append(result, e)
		}
	}
	return result
}

func (v *Validator) checkSubject(subject hexapolicy.SubjectInfo, polIndex int) []ValidationError {
	var vErrs []ValidationError
	// Check that the subject entity type is valid
	entities := subject.EntityPaths()
	for i, entity := range *entities {
		var errs []error
		val := entity.String()
		// ignore the special case of "any" or "anyAuthenticated"
		if entity.Type == types.RelTypeAny || entity.Type == types.RelTypeAnyAuthenticated {
			continue
		}

		namespace := entity.GetNamespace(v.defNamespace)
		entityType := entity.GetType()
		schema, ok := v.namespaces[namespace]
		if !ok {
			errs = append(errs, errors.New(fmt.Sprintf("invalid subject namespace \"%s\"", namespace)))
		}
		_, ok = schema.EntityTypes[entityType]
		if !ok {
			errs = append(errs, errors.New(fmt.Sprintf("invalid subject entity type: \"%s:%s\"", namespace, entityType)))
		}
		if len(errs) > 0 {
			verr := ValidationError{
				PolIndex:    polIndex,
				ValIndex:    i,
				ElementName: "subjects",
				Value:       val,
				Errs:        errs,
			}
			vErrs = append(vErrs, verr)
		}

	}
	return vErrs
}

func (v *Validator) checkObject(resource hexapolicy.ObjectInfo, polIndex int) *ValidationError {
	// If no object or just the appName (namespace) then object is valid
	if resource.String() == "" || strings.EqualFold(resource.String(), v.defNamespace) {
		return nil
	}

	entity := resource.Entity()
	namespace := entity.GetNamespace(v.defNamespace)
	entityType := entity.GetType()
	schema, ok := v.namespaces[namespace]
	if !ok {
		return &ValidationError{
			PolIndex:    polIndex,
			ValIndex:    0,
			ElementName: "object",
			Value:       resource.String(),
			Errs:        []error{errors.New(fmt.Sprintf("invalid object namespace \"%s\"", namespace))},
		}
	}
	if entityType == "" {
		return &ValidationError{
			PolIndex:    polIndex,
			ValIndex:    0,
			ElementName: "object",
			Value:       resource.String(),
			Errs:        []error{errors.New(fmt.Sprintf("missing object entity type: %s:<type>:%s", namespace, *entity.Id))},
		}
	}
	_, ok = schema.EntityTypes[entityType]
	if !ok {
		return &ValidationError{
			PolIndex:    polIndex,
			ValIndex:    0,
			ElementName: "object",
			Value:       resource.String(),
			Errs:        []error{errors.New(fmt.Sprintf("invalid object entity type: %s:%s", namespace, entityType))},
		}
	}

	return nil
}

func (v *Validator) checkAction(policy hexapolicy.PolicyInfo, polIndex int) []ValidationError {
	var vErrs []ValidationError
	for i, action := range policy.Actions {
		var errs []error
		entity := action.EntityPath()
		namespace := entity.GetNamespace(v.defNamespace)
		schema, ok := v.namespaces[namespace]
		if !ok {
			errs = append(errs, errors.New(fmt.Sprintf("invalid namespace \"%s\"", namespace)))
		}
		// Check that the action exists:
		actionType, ok := schema.Actions[entity.GetId()]
		if !ok {
			errs = append(errs, errors.New(fmt.Sprintf("invalid action \"%s\"", entity.String())))
		}

		terrs := v.checkAppliesTo(namespace, actionType.AppliesTo, policy)
		if terrs != nil {
			errs = append(errs, terrs...)
		}
		if len(errs) > 0 {
			vErrs = append(vErrs, ValidationError{
				PolIndex:    polIndex,
				ValIndex:    i,
				ElementName: "actions",
				Value:       action.String(),
				Errs:        errs,
			})
		}
	}
	return vErrs
}

var specialEntities []string = []string{"subject", "action", "resource", "principal"}

func (v *Validator) checkOperand(operand types.Value) (string, error) {
	switch value := operand.(type) {
	case types.Entity:
		namespace := value.GetNamespace(v.defNamespace)
		schema, ok := v.namespaces[namespace]
		if !ok {
			return "error", errors.New(fmt.Sprintf("invalid namespace \"%s\" for %s", namespace, value.String()))
		}

		if slices.Contains(specialEntities, strings.ToLower(*value.Id)) { // checks for subject, principal, action, resource
			return policyInfoModel.TypeRecord, nil
		}

		for _, t := range specialEntities {
			if strings.HasPrefix(*value.Id, fmt.Sprintf("%s%s", t, ".")) { // checks for attributes on special entities
				return policyInfoModel.TypeRecord, nil
			}
		}

		eTypeId := value.GetType()
		_, ok = schema.EntityTypes[eTypeId]
		if !ok {
			return "error", errors.New(fmt.Sprintf("invalid condition entity type: %s", value.String()))
		}

		if value.IsPath() {
			attr := schema.FindAttrType(value)
			if attr == nil {
				return "error", errors.New(fmt.Sprintf("invalid condition attribute: %s", value.String()))
			}
			return attr.Type, nil
		}
		return policyInfoModel.TypeRecord, nil

	case types.String:
		return policyInfoModel.TypeString, nil
	case types.Boolean:
		return policyInfoModel.TypeBool, nil
	case types.Date:
		return policyInfoModel.TypeDate, nil
	case types.Numeric:
		return policyInfoModel.TypeLong, nil
	}
	return "error", errors.New("invalid operand")
}

func (v *Validator) checkExpression(expression parser.Expression) []error {
	var errs []error
	switch exp := expression.(type) {
	case parser.AttributeExpression:
		lType, err := v.checkOperand(exp.AttributePath)
		if err != nil {
			errs = append(errs, err)
		}
		rType := "na"
		if exp.CompareValue != nil {
			rType, err = v.checkOperand(exp.CompareValue)
			if err != nil {
				errs = append(errs, err)
			}
		}
		if errs != nil {
			break
		}

		switch exp.Operator {
		case parser.PR:
			// do nothing
		case parser.EQ, parser.NE, parser.GT, parser.GE, parser.LT, parser.LE:
			// can only compare like types
			if !strings.EqualFold(lType, rType) {
				errs = append(errs, errors.New(fmt.Sprintf("expression \"%s\" has mis-matched attribute types: %s and %s", expression.String(), lType, rType)))
			}
		case parser.SW, parser.EW:
			if !strings.EqualFold(lType, policyInfoModel.TypeString) {
				errs = append(errs, errors.New(fmt.Sprintf("expression \"%s\" requires String comparators (%s is %s)", expression.String(), exp.AttributePath.String(), lType)))
			}
			if !strings.EqualFold(rType, policyInfoModel.TypeString) {
				errs = append(errs, errors.New(fmt.Sprintf("expression \"%s\" requires String comparators (%s is %s)", expression.String(), exp.CompareValue.String(), rType)))
			}
		case parser.CO, parser.IN:
			errFmt := "expression \"%s\" requires an Entity or String comparator (%s is %s)"
			if !strings.EqualFold(lType, policyInfoModel.TypeRecord) && !strings.EqualFold(lType, policyInfoModel.TypeString) {
				errs = append(errs, errors.New(fmt.Sprintf(errFmt, expression.String(), exp.AttributePath.String(), lType)))
			} else if !strings.EqualFold(rType, policyInfoModel.TypeRecord) && !strings.EqualFold(rType, policyInfoModel.TypeString) {
				errs = append(errs, errors.New(fmt.Sprintf(errFmt, expression.String(), exp.CompareValue.String(), rType)))
			}
		}

	case parser.ValuePathExpression:
		// TODO Need to verify
		// 1. Main attribute is valid
		// 2. Each attribute in the filter is valid
		// 3. if specified, the sub-attribute is valid
		// 4. The comparison is valid.
		errs = append(errs, errors.New(fmt.Sprintf("valuePath expressions \"%s\" are not supported", exp.String())))

	}
	return errs
}

func (v *Validator) checkConditions(policy hexapolicy.PolicyInfo, polIndex int) []ValidationError {
	var errs []error
	var vErrs []ValidationError
	if policy.Condition == nil {
		return nil
	}

	if policy.Condition.Action != "" {
		match := false
		for _, element := range []string{"allow", "deny", "ALLOW", "DENY"} {
			if element == policy.Condition.Action {
				match = true
			}
		}
		if !match {
			vErr := ValidationError{
				PolIndex:    polIndex,
				ValIndex:    0,
				ElementName: "condition-action",
				Value:       policy.Condition.Action,
				Errs:        []error{errors.New(fmt.Sprintf("invalid condition action: %s, must be one of allow|deny", policy.Condition.Action))},
			}
			vErrs = append(vErrs, vErr)
		}
	}

	tree, err := policy.Condition.Ast()
	if err != nil {
		errs = append(errs, err)
	} else {
		expressions := conditions.FindEntityUses(tree)
		for _, exp := range expressions {
			expressionErrs := v.checkExpression(exp)
			if expressionErrs != nil {
				errs = append(errs, expressionErrs...)
			}
		}
	}

	if len(errs) > 0 {
		vErr := ValidationError{
			PolIndex:    polIndex,
			ValIndex:    0,
			ElementName: "condition",
			Value:       strconv.Quote(policy.Condition.Rule),
			Errs:        errs,
		}
		vErrs = append(vErrs, vErr)
	}
	return vErrs
}

func (v *Validator) checkAppliesTo(actionNamespace string, appliesTo policyInfoModel.AppliesType, policy hexapolicy.PolicyInfo) []error {
	var errs []error
	// Check Principals
	principalTypes := appliesTo.PrincipalTypes

	// assume that if principalType is nil that validation is ok
	if principalTypes != nil {
		entities := policy.Subjects.EntityPaths()
		principals := *principalTypes

		for _, entity := range *entities {
			namespace := entity.GetNamespace(v.defNamespace)

			if entity.Type == types.RelTypeAny || entity.Type == types.RelTypeAnyAuthenticated || entity.Type == types.RelTypeEmpty {
				continue // skip validation for any or anyauthenticated or empty
			}
			contains := false
			for _, principal := range principals {
				if strings.Contains(principal, ":") {
					if strings.EqualFold(principal, fmt.Sprintf("%s:%s", namespace, entity.GetType())) {
						contains = true
					}
				} else {
					if actionNamespace == namespace &&
						strings.EqualFold(entity.GetType(), principal) {
						contains = true
					}
				}
			}
			if !contains {
				errs = append(errs, errors.New(fmt.Sprintf("policy cannot be applied to subject \"%s\", must be one of %+q", entity.String(), principals)))
			}
		}

	}

	// Check Object
	resourceTypes := appliesTo.ResourceTypes
	if resourceTypes != nil {
		entity := policy.Object.Entity()
		if entity.Type != types.RelTypeEmpty {
			namespace := entity.GetNamespace(v.defNamespace)
			resTypes := *resourceTypes
			contains := false
			for _, resType := range resTypes {
				if strings.Contains(resType, ":") {
					if strings.EqualFold(resType, fmt.Sprintf("%s:%s", namespace, entity.GetType())) {
						contains = true
					}
				} else {
					if actionNamespace == namespace &&
						strings.EqualFold(entity.GetType(), resType) {
						contains = true
					}
				}
			}
			if !contains {
				errs = append(errs, errors.New(fmt.Sprintf("policy cannot be applied to object type \"%s\", must be one of %+q", policy.Object.String(), resTypes)))
			}
		}

	}
	return errs
}
