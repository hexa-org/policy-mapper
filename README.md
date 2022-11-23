# Hexa Policy Conditions Support

The Hexa Policy Conditions support project provides support for IDQL Policy Conditions (see 
[IDQL Specification section 4.7](https://github.com/hexa-org/policy/blob/main/specs/IDQL-core-specification.md#47-condition)) 
intended for use by [Hexa Policy Orchestrator](https://github.com/hexa-org/policy-orchestrator).

To use this mapper. instantiate a mapper for a particular provider and use the MapConditionToProvider and
MapProviderToCondition to translate in either direction.

```go
import (
	"github.com/hexa-org/policySupport/conditions"
    "github.com/hexa-org/policySupport/conditions/googlecloud"
)

func main() {
	mapper := GoogleConditionMapper{}
	
	idqlCondition := conditions.ConditionInfo{
		Rule: "subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or subject.country_code eq \"IR\")",
		Action: "allow",
    }
	
	// Map to Google CEL Language
	celString, err := mapper.MapConditionToProvider(idqlCondition)
	
	// Convert a CEL expression back into an IDQL Condition
	condition, err := mapper.MapProviderToCondition(celString)
	
	/*
	 Note that in the above code, idqlCondition.Rule should be logically equivalent to condition.Rule. Some differences
	 may occur due to case normalization, removal of unnecessary parentheses, etc.
	*/
}
```

## Getting Involved

Please see the README on the main [Policy Orchestrator](https://github.com/hexa-org/policy-orchestrator) project.

For issues related to condition mapping and backlog please see the project and issues section of this project.

