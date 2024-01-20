package main

import (
	"fmt"

	"github.com/hexa-org/policy-mapper/mapper/conditionLangs/gcpcel"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
)

func main() {
	mapper := gcpcel.GoogleConditionMapper{NameMapper: conditions.NewNameMapper(map[string]string{
		"a":       "b",
		"req.sub": "userid",
	})}

	idqlCondition := conditions.ConditionInfo{
		Rule:   "subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or subject.country_code eq \"IR\")",
		Action: "allow",
	}

	// Map to Google CEL Language
	celString, err := mapper.MapConditionToProvider(idqlCondition)
	if err != nil {
		fmt.Println(err.Error())
		panic(-1)
	}
	fmt.Println("Mapped Google CEL format: " + celString)

	// Convert a CEL expression back into an IDQL Condition
	condition, err := mapper.MapProviderToCondition(celString)
	if err != nil {
		fmt.Println(err.Error())
		panic(-1)
	}
	fmt.Println(fmt.Sprintf("Mapped IDQL Condition: %v", condition))
}
