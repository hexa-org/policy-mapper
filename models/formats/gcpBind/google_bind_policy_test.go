package gcpBind_test

import (
    "encoding/json"
    "fmt"

    "math/rand"
    "os"
    "path/filepath"
    "runtime"
    "testing"
    "time"

    "github.com/hexa-org/policy-mapper/models/formats/gcpBind"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
    "github.com/stretchr/testify/assert"

    "google.golang.org/api/iam/v1"
)

var gcpMapper = gcpBind.New(map[string]string{})

func getIdqlFile() string {
    _, file, _, _ := runtime.Caller(0)
    return filepath.Join(file, "../test/data.json")
}

func TestProduceAndParseGcp(t *testing.T) {
    var err error
    policies, err := hexapolicysupport.ParsePolicyFile(getIdqlFile())
    assert.NoError(t, err, "File %s not parsed", getIdqlFile())

    bindAssignments := gcpMapper.MapPoliciesToBindings(policies)

    fmt.Println("iam.Binding:")
    PrintObj(bindAssignments[0].Bindings[0])
    fmt.Println("BindAssignment:")
    PrintObj(bindAssignments[0])
    fmt.Println("[]BindAssignment")
    PrintObj(bindAssignments)
    rand.Seed(time.Now().UnixNano())
    dir := t.TempDir()

    runId := rand.Uint64()

    // We will generate 3 output variants to test the parser

    bindingAssignFile := filepath.Join(dir, fmt.Sprintf("bindAssign-%d.json", runId))
    bindingsAssignFile := filepath.Join(dir, fmt.Sprintf("bindAssigns-%d.json", runId))
    bindingFile := filepath.Join(dir, fmt.Sprintf("binding-%d.json", runId))

    // Write a single binding
    assert.NoError(t, WriteObj(bindingFile, bindAssignments[0].Bindings[0]), "Single bind write")

    // Write out a single bind assignment
    assert.NoError(t, WriteObj(bindingAssignFile, bindAssignments[0]), "Single bind assignment write")

    // Write out all assignments
    assert.NoError(t, WriteObj(bindingsAssignFile, bindAssignments), "Single bind assignment write")

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

    assert.Equal(t, 4, len(bindAssigns), "Check 4 GcpBindAssignment returned")
    p1 := bindAssigns[0]
    p2 := bindAssigns[1]
    resId1 := p1.ResourceId
    resId2 := p2.ResourceId

    assert.NotEqual(t, resId1, resId2, "Check resource ids are different")

    copyPolcies, err := gcpMapper.MapBindingAssignmentsToPolicy(bindAssigns)

    output, err := json.MarshalIndent(copyPolcies, "", "  ")
    fmt.Println(string(output))
    assert.NoError(t, err, "Check error after mapping bindings back to policies")
    assert.Equal(t, 5, len(copyPolcies), "5 policies returned")

    found := false
    for _, policy := range bindAssigns {
        if policy.ResourceId == "754290878449499554" {
            bindings := policy.Bindings
            assert.NotNil(t, bindings, "Should be bindings")

            role := bindings[0].Role
            assert.Equal(t, "roles/iap.httpsResourceAccessor", role, "Should be roles/iap.httpsResourceAccessor")
            found = true
            break
        }
    }
    assert.True(t, found, "Specific iap policy found")

}

func TestReadGcp(t *testing.T) {
    _, file, _, _ := runtime.Caller(0)
    assignmentsFile := filepath.Join(file, "../test/test_assignments.json")
    assignmentFile := filepath.Join(file, "../test/test_assignment.json")
    bindingFile := filepath.Join(file, "../test/test_binding.json")

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

func PrintObj(data interface{}) {
    var polBytes []byte
    switch pol := data.(type) {
    case iam.Binding:
        polBytes, err := json.MarshalIndent(pol, "", "  ")
        if err != nil {
            fmt.Println(err.Error())
        }
        //	fmt.Println(string(polBytes))
        fmt.Println(string(polBytes))
        return

    case []*gcpBind.BindAssignment, *gcpBind.BindAssignment:
        polBytes, err := json.MarshalIndent(pol, "", "  ")
        if err != nil {
            fmt.Println(err.Error())
        }
        fmt.Println(string(polBytes))
        return
    }

    fmt.Println(string(polBytes))
    return

}

func WriteObj(path string, data interface{}) error {
    var polBytes []byte
    switch pol := data.(type) {
    case iam.Binding:
        polBytes, err := json.MarshalIndent(pol, "", "  ")
        if err != nil {
            fmt.Println(err.Error())
        }
        //	fmt.Println(string(polBytes))
        return os.WriteFile(path, polBytes, 0644)

    case []*gcpBind.BindAssignment, *gcpBind.BindAssignment:
        polBytes, err := json.MarshalIndent(pol, "", "  ")
        if err != nil {
            fmt.Println(err.Error())
        }
        //	fmt.Println(string(polBytes))
        return os.WriteFile(path, polBytes, 0644)
    }

    return os.WriteFile(path, polBytes, 0644)

}
