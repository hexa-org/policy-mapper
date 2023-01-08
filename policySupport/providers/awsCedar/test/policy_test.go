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

	assert.Equal(t, 5, len(cedarPols.Policies), "Should be 5 policies generated")

	fmt.Printf("%v Cedar Policies Returned\n", len(cedarPols.Policies))
	for k, v := range cedarPols.Policies {
		fmt.Printf("Policy# %v\n", k)
		polString := v.String()
		fmt.Println(polString)
	}

	assert.Equal(t, 2, len(cedarPols.Policies[0].Head.Actions.Action), "Should be 2 actions in policy 0")
	assert.Equal(t, 1, len(cedarPols.Policies[0].Conditions), "Should be 1 condition")
	/*
		rand.Seed(time.Now().UnixNano())
		dir := t.TempDir()

		runId := rand.Uint64()

		// We will generate 3 output variants to test the parser

		bindingAssignFile := filepath.Join(dir, fmt.Sprintf("bindAssign-%d.json", runId))
		bindingsAssignFile := filepath.Join(dir, fmt.Sprintf("bindAssigns-%d.json", runId))
		bindingFile := filepath.Join(dir, fmt.Sprintf("binding-%d.json", runId))

		//Write a single binding
		assert.NoError(t, WriteObj(bindingFile, cedarPols[0].Bindings[0]), "Single bind write")

		//Write out a single bind assignment
		assert.NoError(t, WriteObj(bindingAssignFile, cedarPols[0]), "Single bind assignment write")

		//Write out all assignments
		assert.NoError(t, WriteObj(bindingsAssignFile, cedarPols), "Single bind assignment write")

		// Parse a simple binding
		bindRead, err := gcpBind.ParseFile(bindingFile)
		assert.NoError(t, err, "Read a single binding")

		assert.Equal(t, 1, len(bindRead), "Check 1 GcpBindAssignment returned")
		resId := bindRead[0].ResourceId
		assert.Equal(t, "", resId)

		// Parse a single assignment
		bindAssign, err := gcpBind.ParseFile(bindingAssignFile)
		assert.NoError(t, err, "Read a single binding assignment")

		assert.Equal(t, 1, len(bindAssign), "Check 1 GcpBindAssignment returned")
		resId = bindAssign[0].ResourceId
		assert.NotEqual(t, "", resId)

		// Parse a multiple assignment
		bindAssigns, err := gcpBind.ParseFile(bindingsAssignFile)
		assert.NoError(t, err, "Read multiple binding assignments")

		assert.Equal(t, 3, len(bindAssigns), "Check 4 GcpBindAssignment returned")
		p1 := bindAssigns[0]
		p2 := bindAssigns[1]
		resId1 := p1.ResourceId
		resId2 := p2.ResourceId

		assert.NotEqual(t, resId1, resId2, "Check resource ids are different")

		copyPolcies, err := cedarMapper.MapBindingAssignmentsToPolicy(bindAssigns)

		output, err := json.MarshalIndent(copyPolcies, "", "  ")
		fmt.Println(string(output))
		assert.NoError(t, err, "Check error after mapping bindings back to policies")
		assert.Equal(t, 4, len(copyPolcies), "4 policies returned")

	*/
}

/*
func TestReadGcp(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	assignmentsFile := filepath.Join(file, "../resources/test_assignments.json")
	assignmentFile := filepath.Join(file, "../resources/test_assignment.json")
	bindingFile := filepath.Join(file, "../resources/test_binding.json")

	assignment, err := gcpBind.ParseFile(assignmentFile)
	assert.NoError(t, err, "Parsing Assignment error")
	assert.Equal(t, 1, len(assignment), "1 assignment should be returned")

	assignment, err = gcpBind.ParseFile(assignmentsFile)
	assert.NoError(t, err, "Parsing Multi Assignments error")
	assert.Equal(t, 3, len(assignment), "3 assignment should be returned")

	assignment, err = gcpBind.ParseFile(bindingFile)
	assert.NoError(t, err, "Parsing Binding error")
	assert.Equal(t, 1, len(assignment), "1 assignment should be returned")
	assert.Equal(t, "", assignment[0].ResourceId, "should have no resource id value")
}

*/

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

	file := getTestFile("../resources/cedarTest.txt")
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

}
