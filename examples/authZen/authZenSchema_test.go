package authZen

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/pimValidate"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
	"github.com/stretchr/testify/assert"
)

func TestSchema(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	testSchemaFile := filepath.Join(file, "../authZenSchema.json")
	schemaBytes, err := os.ReadFile(testSchemaFile)
	assert.NoError(t, err)

	validator, err := pimValidate.NewValidator(schemaBytes, "TodoApp")
	assert.NoError(t, err)

	policyFile := filepath.Join(file, "../data.json")
	policyBytes, err := os.ReadFile(policyFile)
	assert.NoError(t, err)

	policies, err := hexapolicysupport.ParsePolicies(policyBytes)

	for _, policy := range policies {
		reporterrs := validator.ValidatePolicy(policy)
		if reporterrs != nil {
			for _, report := range reporterrs {
				fmt.Println(report.Error())
			}
		}
	}

}
