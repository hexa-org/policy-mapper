package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/sdk"
)

func main() {
	keybytes, err := os.ReadFile("awsCredential.txt")
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

	for alias := range integration.Apps {
		policies := getAndPrintPolicies(integration, alias)

		// Note that the returned policies object has the "app" alias included as policies.App.
		setPolicies(integration, policies)
	}

}

func getAndPrintPolicies(integration *sdk.Integration, alias string) *hexapolicy.Policies {

	fmt.Println("PAP " + alias)

	policies, err := integration.GetPolicies(alias)
	if err != nil {
		fmt.Println("Error retrieving policies: " + err.Error())
	}
	jsonBytes, _ := json.MarshalIndent(policies, "", "  ")
	fmt.Println("IDQL returned:")
	fmt.Println(string(jsonBytes))

	return policies
}

func setPolicies(integration *sdk.Integration, policies *hexapolicy.Policies) {

	status, err := integration.SetPolicyInfo(*policies.App, policies.Policies)
	if err != nil {
		fmt.Println("Error getting policy: " + err.Error())
		panic(-1)
	}
	fmt.Println("Request completed with http status " + strconv.Itoa(status))
}
