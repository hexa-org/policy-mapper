package main

import (
	"encoding/json"
	"fmt"

	"github.com/hexa-org/policy-mapper/sdk"
)

func getPolicies(integration *sdk.Integration) {

	apps, err := integration.GetPolicyApplicationPoints(nil)
	if err != nil {
		panic(-1)
	}

	for _, app := range apps {

		fmt.Println("PAP " + app.ObjectID)

		policies, err := integration.GetPolicies(app.ObjectID)
		if err != nil {
			fmt.Println("Error retrieving policies: " + err.Error())
		}
		jsonBytes, _ := json.MarshalIndent(policies, "", "  ")
		fmt.Println("IDQL returned:")
		fmt.Println(string(jsonBytes))
	}
}
