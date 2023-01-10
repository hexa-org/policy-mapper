package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	policysupport "policy-conditions/policySupport"
	"policy-conditions/policySupport/providers/awsCedar"
	"runtime"
	"testing"
)

var cedarMapper = awsCedar.New(map[string]string{})

func getTestFile(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(file, name)
}

func TestProduceAndParseCedar(t *testing.T) {
	var err error
	policies, err := policysupport.ParsePolicyFile(getTestFile("../resources/data.json"))
	assert.NoError(t, err, "File %s not parsed", getTestFile("../resources/data.json"))

	cedarPols, err := cedarMapper.MapPoliciesToCedar(policies)

	assert.Equal(t, 7, len(cedarPols.Policies), "Should be 5 policies generated")

	fmt.Printf("%v Cedar Policies Returned\n", len(cedarPols.Policies))
	for k, v := range cedarPols.Policies {
		fmt.Printf("Policy# %v\n", k)
		polString := v.String()
		fmt.Println(polString)
	}

	res := cedarPols.Policies[0].Head.Resource

	assert.Equal(t, "==", cedarPols.Policies[0].Head.Actions.Operator, "Should be ==")
	assert.Equal(t, "Action::\"view\"", cedarPols.Policies[0].Head.Actions.Action, "Should be Action::\"view\"")
	assert.Equal(t, 1, len(cedarPols.Policies[0].Conditions), "Should be 1 condition")
	assert.Nil(t, res, "Resource should be nil")

}

func TestParserSingle(t *testing.T) {

	file := getTestFile("../resources/cedarSingle.txt")
	cedarBytes, err := os.ReadFile(file)
	if err != nil {
		assert.Fail(t, "Error opening cedar test file: "+err.Error())
	}

	cedarAst, err := cedarMapper.ParseCedarBytes(cedarBytes)
	if err != nil {
		fmt.Println(err.Error())
	}
	assert.NoError(t, err)

	fmt.Printf("Polcies returned: %v\n", len(cedarAst.Policies))

	fmt.Printf("%v Cedar Policies Returned\n", len(cedarAst.Policies))
	for k, v := range cedarAst.Policies {
		fmt.Printf("Policy# %v\n", k)
		polString := v.String()
		fmt.Println(polString)
	}

	assert.Equal(t, 2, len(cedarAst.Policies[0].Head.Actions.Actions), "Should be two actions")

}

func TestParserMulti(t *testing.T) {

	file := getTestFile("../resources/cedarMulti.txt")
	cedarBytes, err := os.ReadFile(file)
	if err != nil {
		assert.Fail(t, "Error opening cedar test file: "+err.Error())
	}

	cedarAst, err := cedarMapper.ParseCedarBytes(cedarBytes)
	if err != nil {
		fmt.Println(err.Error())
	}
	assert.NoError(t, err)

	fmt.Printf("Polcies returned: %v\n", len(cedarAst.Policies))

	fmt.Printf("%v Cedar Policies Returned\n", len(cedarAst.Policies))
	for k, v := range cedarAst.Policies {
		fmt.Printf("Policy# %v\n", k)
		polString := v.String()
		fmt.Println(polString)
	}
	assert.Equal(t, 4, len(cedarAst.Policies), "Should be 4 policies parsed")
	assert.Equal(t, 2, len(cedarAst.Policies[0].Head.Actions.Actions), "Should be two actions")

	condString := cedarAst.Policies[3].Conditions[0].String()
	assert.Contains(t, condString, " true ", "Check boolean not quoted")
	assert.Contains(t, condString, " < ", "Check less than present")
}

func TestParserToHexa(t *testing.T) {
	file := getTestFile("../resources/cedarMulti.txt")

	idql, err := cedarMapper.ParseFile(file)
	if err != nil {
		assert.NoError(t, err, "error parsing and mapping of cedar bytes")

	}

	condString := idql.Policies[3].Condition.Rule
	assert.Contains(t, condString, " true", "Check boolean not quoted")
	assert.Contains(t, condString, " lt ", "Check less than present")

}

func TestGcpMapped(t *testing.T) {
	file := getTestFile("../resources/test2.json")
	policies, err := policysupport.ParsePolicyFile(file)
	assert.NoError(t, err)

	cedarPols, err := cedarMapper.MapPoliciesToCedar(policies)
	assert.NoError(t, err)
	assert.Equal(t, 7, len(cedarPols.Policies))

}
