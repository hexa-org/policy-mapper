package pimValidate

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hexa-org/policy-mapper/models/policyInfoModel"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/parser"
)

type Validator struct {
	namespaces   policyInfoModel.Namespaces
	defNamespace string
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
		if entity.Type == parser.RelTypeAny || entity.Type == parser.RelTypeAnyAuthenticated {
			continue
		}

		namespace := entity.GetNamespace(v.defNamespace)
		entityType := entity.GetType()
		schema, ok := v.namespaces[namespace]
		if !ok {
			errs = append(errs, errors.New(fmt.Sprintf("invalid subject PIM namespace (%s)", namespace)))
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

	entity := resource.EntityPath()
	namespace := entity.GetNamespace(v.defNamespace)
	entityType := entity.GetType()
	schema, ok := v.namespaces[namespace]
	if !ok {
		return errors.New(fmt.Sprintf("invalid object PIM namespace (%s)", namespace))
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
			errs = append(errs, errors.New(fmt.Sprintf("invalid PIM namespace (%s)", namespace)))
			continue
		}
		// Check that the action exists:
		actionType, ok := schema.Actions[*entity.Id]
		if !ok {
			errs = append(errs, errors.New(fmt.Sprintf("invalid action type: %s:Action:%s", namespace, *entity.Id)))
			continue
		}

		terrs := v.checkAppliesTo(namespace, actionType.AppliesTo, policy)
		if terrs != nil {
			errs = append(errs, terrs...)
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

			if entity.Type == parser.RelTypeAny || entity.Type == parser.RelTypeAnyAuthenticated || entity.Type == parser.RelTypeEmpty {
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
				errs = append(errs, errors.New(fmt.Sprintf("invalid principal type (%s:%s), must be one of %+q", namespace, entity.GetType(), principals)))
			}
		}

	}

	// Check Object
	resourceTypes := appliesTo.ResourceTypes
	if resourceTypes != nil {
		entity := policy.Object.EntityPath()
		if entity.Type != parser.RelTypeEmpty {
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
				errs = append(errs, errors.New(fmt.Sprintf("invalid object type (%s:%s), must be one of %+q", namespace, entity.GetType(), resTypes)))
			}
		}

	}
	return errs
}
