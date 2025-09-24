package pimValidate

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/hexa-org/policy-mapper/models/policyInfoModel"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions/parser"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/types"
)

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

// ValidatePolicy checks `policy` (PolicyInfo) against the loaded Policy Information Model.
// When provided, appNamespace is used to default the main namespace for entities referenced in policy. For example
// if appNamespace is `PhotoApp`, an entity of `Photo:myphoto.jpg` will be located under `PhotoApp`
// If appNamespace is not provided, then each EntityPaths must contain the namespace as part of the type (e.g. PhotoApp:Photo:myphoto.jpg)
func (v *Validator) ValidatePolicy(policy hexapolicy.PolicyInfo) []error {
	var errs []error

	tErrs := v.checkSubject(policy.Subjects)
	if tErrs != nil {
		errs = append(errs, tErrs...)
	}

	err := v.checkObject(policy.Object)
	if err != nil {
		errs = append(errs, err)
	}

	tErrs = v.checkAction(policy)
	if tErrs != nil {
		errs = append(errs, tErrs...)
	}

	tErrs = v.checkConditions(policy)
	if tErrs != nil {
		errs = append(errs, tErrs...)
	}

	return errs
}

// ValidatePolicies validates a set of policies and returns a map whose index is as string containing either
// the policyId of a policy with errors or an index number of the policies original index in Policies
func (v *Validator) ValidatePolicies(policies hexapolicy.Policies) map[string][]error {
	var res map[string][]error

	for i, policy := range policies.Policies {
		id := fmt.Sprintf("Policy-%d", i)
		if policy.Meta.PolicyId != nil && *policy.Meta.PolicyId != "" {
			id = fmt.Sprintf("Policy-%s", *policy.Meta.PolicyId)
		}
		errs := v.ValidatePolicy(policy)
		if errs != nil {
			if res == nil {
				res = make(map[string][]error)
			}
			res[id] = errs
		}
	}
	return res
}

func (v *Validator) checkSubject(subject hexapolicy.SubjectInfo) []error {
	var errs []error
	// Check that the subject entity type is valid
	entities := subject.EntityPaths()
	for _, entity := range *entities {
		// ignore the special case of "any" or "anyAuthenticated"
		if entity.Type == types.RelTypeAny || entity.Type == types.RelTypeAnyAuthenticated {
			continue
		}

		namespace := entity.GetNamespace(v.defNamespace)
		entityType := entity.GetType()
		schema, ok := v.namespaces[namespace]
		if !ok {
			errs = append(errs, errors.New(fmt.Sprintf("invalid subject namespace \"%s\"", namespace)))
			continue
		}
		_, ok = schema.EntityTypes[entityType]
		if !ok {
			errs = append(errs, errors.New(fmt.Sprintf("invalid subject entity type: %s:%s", namespace, entityType)))
		}
	}
	return errs
}

func (v *Validator) checkObject(resource hexapolicy.ObjectInfo) error {
	// If no object or just the appName (namespace) then object is valid
	if resource.String() == "" || strings.EqualFold(resource.String(), v.defNamespace) {
		return nil
	}

	entity := resource.Entity()
	namespace := entity.GetNamespace(v.defNamespace)
	entityType := entity.GetType()
	schema, ok := v.namespaces[namespace]
	if !ok {
		return errors.New(fmt.Sprintf("invalid object namespace \"%s\"", namespace))
	}
	if entityType == "" {
		return errors.New(fmt.Sprintf("missing object entity type: %s:<type>:%s", namespace, *entity.Id))
	}
	_, ok = schema.EntityTypes[entityType]
	if !ok {
		return errors.New(fmt.Sprintf("invalid object entity type: %s:%s", namespace, entityType))
	}

	return nil
}

func (v *Validator) checkAction(policy hexapolicy.PolicyInfo) []error {
	var errs []error
	for _, action := range policy.Actions {
		entity := action.EntityPath()
		namespace := entity.GetNamespace(v.defNamespace)
		schema, ok := v.namespaces[namespace]
		if !ok {
			errs = append(errs, errors.New(fmt.Sprintf("invalid namespace \"%s\"", namespace)))
			continue
		}
		// Check that the action exists:
		actionType, ok := schema.Actions[entity.GetId()]
		if !ok {
			errs = append(errs, errors.New(fmt.Sprintf("invalid action \"%s\"", entity.String())))
			continue
		}

		terrs := v.checkAppliesTo(namespace, actionType.AppliesTo, policy)
		if terrs != nil {
			errs = append(errs, terrs...)
		}
	}
	return errs
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

func (v *Validator) checkConditions(policy hexapolicy.PolicyInfo) []error {
	var errs []error
	if policy.Condition == nil {
		return nil
	}

	ast, err := policy.Condition.Ast()
	if err != nil {
		errs = append(errs, err)
	} else {
		expressions := conditions.FindEntityUses(ast)
		for _, exp := range expressions {
			expressionErrs := v.checkExpression(exp)
			if expressionErrs != nil {
				errs = append(errs, expressionErrs...)
			}
		}
	}

	return errs
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
