package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/sdk"
)

func main() {
	keybytes, err := os.ReadFile("awscred.txt")
	if err != nil {
		panic(-1)
	}

	info := policyprovider.IntegrationInfo{
		Name: sdk.ProviderTypeAvp,
		Key:  keybytes,
	}

	integration, err := sdk.OpenIntegration(sdk.WithIntegrationInfo(info))
	if err != nil {
		fmt.Println("Error opening integration: " + err.Error())
		panic(-1)
	}

	apps, err := integration.GetPolicyApplicationPoints(nil)
	if err != nil {
		panic(-1)
	}

	for _, app := range apps {
		jsonBytes, _ := json.MarshalIndent(app, "", "  ")
		fmt.Println(string(jsonBytes))
	}

	getPolicies(integration)

	setPolicies(integration)
}
