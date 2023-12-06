package awsCedar_test

import (
    "fmt"
    "os"
    "path/filepath"
    "runtime"
    "testing"

    "github.com/hexa-org/policy-mapper/mapper/formats/awsCedar"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
    "github.com/stretchr/testify/assert"
)

var cedarMapper = awsCedar.New(map[string]string{})

func getTestFile(name string) string {
    _, file, _, _ := runtime.Caller(0)
    return filepath.Join(file, name)
}

func TestProduceAndParseCedar(t *testing.T) {
    var err error
    policies, err := hexapolicysupport.ParsePolicyFile(getTestFile("../test/data.json"))
    assert.NoError(t, err, "File %s not parsed", getTestFile("../test/data.json"))

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

    file := getTestFile("../test/cedarSingle.txt")
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

func TestParserTemplate(t *testing.T) {
    file := getTestFile("../test/cedarTemplate.txt")
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

    assert.Equal(t, 1, len(cedarAst.Policies[0].Head.Actions.Actions), "Should be one action")
}

func TestParserWhenTrue(t *testing.T) {
    file := getTestFile("../test/cedarWhenTrue.txt")
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

    hexaPols, err := cedarMapper.MapCedarPoliciesToIdql(cedarAst)
    assert.NoError(t, err, "Should be no error mapping to idql")
    assert.Len(t, hexaPols.Policies, 1, "Expect 1 policy")
    assert.Equal(t, 4, len(cedarAst.Policies[0].Head.Actions.Actions), "Should be one action")
}

func TestParserMulti(t *testing.T) {

    file := getTestFile("../test/cedarMulti.txt")
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
    file := getTestFile("../test/cedarMulti.txt")

    idql, err := cedarMapper.ParseFile(file)
    if err != nil {
        assert.NoError(t, err, "error parsing and mapping of cedar bytes")

    }

    condString := idql.Policies[3].Condition.Rule
    assert.Contains(t, condString, " true", "Check boolean not quoted")
    assert.Contains(t, condString, " lt ", "Check less than present")

}

func TestGcpMapped(t *testing.T) {
    file := getTestFile("../test/testGcpIdql.json")
    policies, err := hexapolicysupport.ParsePolicyFile(file)
    assert.NoError(t, err)

    cedarPols, err := cedarMapper.MapPoliciesToCedar(policies)
    assert.NoError(t, err)
    assert.Equal(t, 7, len(cedarPols.Policies))

}

func TestMultiCond(t *testing.T) {
    file := getTestFile("../test/cedarMultiCond.txt")
    idql, err := cedarMapper.ParseFile(file)
    if err != nil {
        assert.NoError(t, err, "error parsing and mapping of cedar bytes")

    }

    condString := idql.Policies[0].Condition.Rule

    assert.Equal(t, "(not(resource.tag eq \"private\")) && (resource.type eq \"file\")", condString)
    fmt.Println(condString)

}
