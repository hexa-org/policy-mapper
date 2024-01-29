package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
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

	integration, err := sdk.OpenIntegration(&info)
	if err != nil {
		fmt.Println("Error opening integration: " + err.Error())
		panic(-1)
	}

	hexaPolicies, err := hexapolicysupport.ParsePolicyFile("idqlinput.json")

	status, err := integration.SetPolicyInfo("<alias>", hexaPolicies)
	if err != nil {
		fmt.Println("Error getting policy: " + err.Error())
		panic(-1)
	}
	fmt.Println("Request completed with http status " + strconv.Itoa(status))
}
