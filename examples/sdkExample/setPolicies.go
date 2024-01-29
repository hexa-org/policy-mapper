package main

import (
	"fmt"
	"strconv"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
	"github.com/hexa-org/policy-mapper/sdk"
)

func setPolicies(integration *sdk.Integration) {

	hexaPolicies, err := hexapolicysupport.ParsePolicyFile("idqlinput.json")

	status, err := integration.SetPolicyInfo("<alias>", hexaPolicies)
	if err != nil {
		fmt.Println("Error getting policy: " + err.Error())
		panic(-1)
	}
	fmt.Println("Request completed with http status " + strconv.Itoa(status))
}
