package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
	"github.com/hexa-org/policy-mapper/providers/test"
	"github.com/hexa-org/policy-mapper/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var testLog = log.New(os.Stdout, "HEXA-TEST: ", log.Ldate|log.Ltime)

type testSuite struct {
	suite.Suite
	pd      *ParserData
	testDir string

	Apps     []policyprovider.ApplicationInfo
	Provider policyprovider.V2Provider
	Info     policyprovider.IntegrationInfo
}

func (suite *testSuite) initializeParser() error {
	var err error
	dir, _ := os.MkdirTemp(os.TempDir(), "hexaTest-*")
	suite.testDir = dir

	cli := &CLI{}

	suite.pd, err = initParser(cli) // calls the main init parser
	if err != nil {
		testLog.Printf(err.Error())
	}

	return nil
}

func (suite *testSuite) executeCommand(cmd string, confirmCnt int) ([]byte, error) {
	// args := strings.Split(cmd, " ")
	quoted := false
	args := strings.FieldsFunc(cmd, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}
		return !quoted && r == ' '
	})

	var ctx *kong.Context
	ctx, err := suite.pd.parser.Parse(args)

	if err != nil {
		suite.pd.parser.Errorf("%s", err.Error())
		var errParse *kong.ParseError
		if errors.As(err, &errParse) {
			testLog.Println(err.Error())
			_ = errParse.Context.PrintUsage(false)
			return nil, err
		}
	}

	output := os.Stdout
	input := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdout = w
	var ir, iw *os.File
	if confirmCnt > 0 {
		ir, iw, _ = os.Pipe()
		os.Stdin = ir
		confirm := "Y\n"
		for i := 0; i < confirmCnt; i++ {
			_, _ = iw.Write([]byte(confirm))
		}
		_ = iw.Close()

	}

	err = ctx.Run(&suite.pd.cli.Globals)
	if confirmCnt > 0 {
		os.Stdin = input
		_ = ir.Close()
	}
	_ = w.Close()
	os.Stdout = output

	resultBytes, _ := io.ReadAll(r)
	_ = r.Close()

	return resultBytes, err
}

func TestHexaAdmin(t *testing.T) {
	s := testSuite{}

	// Override sdk to use Mock Provider
	_ = os.Setenv(sdk.EnvTestProvider, sdk.ProviderTypeMock)

	err := s.initializeParser()
	assert.NoError(t, err, "Check parser initialized")

	suite.Run(t, &s)

	testLog.Println("** Testing complete **")
}

func (suite *testSuite) Test0_ConfigInit() {

	testConfigPath := filepath.Join(suite.testDir, ".hexa", "config.json")
	suite.pd.cli.Config = testConfigPath

	config := suite.pd.cli.Data
	assert.NotNil(suite.T(), config, "Check config is not nil")

	err := config.checkConfigPath(&suite.pd.cli.Globals)
	assert.NoError(suite.T(), err, "Check no error config path")

	assert.NotEmpty(suite.T(), suite.pd.cli.ConfigFile, "config file calculated")
	testLog.Println("Tests using Config file: " + suite.pd.cli.ConfigFile)

	err = config.Load(&suite.pd.cli.Globals)
	assert.NoError(suite.T(), err, "Check no error on load")
}

func (suite *testSuite) Test1_AddIntegration() {
	testLog.Println("Test 0 - Testing Add Integration")

	cmd := "add avp test --region=us-west-1 --keyid=1234 --secret=5678"

	res, err := suite.executeCommand(cmd, 1)
	assert.NoError(suite.T(), err, "Check no error after add avp")
	testLog.Println(string(res))

	cmd2 := "add avp test2 --file=./test/testcred.json"
	res2, err := suite.executeCommand(cmd2, 1)
	assert.NoError(suite.T(), err, "Check no error after add avp --file")
	testLog.Println(string(res2))

	keybytes, err := os.ReadFile("./test/testcred.json")
	assert.NoError(suite.T(), err)
	integration1 := suite.pd.cli.Data.GetIntegration("test")
	integration2 := suite.pd.cli.Data.GetIntegration("test")
	assert.Equal(suite.T(), policyprovider.PROVIDER_TYPE_AVP, integration1.Opts.Info.Name, "Type is avp")
	assert.Equal(suite.T(), keybytes, integration1.Opts.Info.Key, "Keybytes matches for integration 1")
	assert.Equal(suite.T(), policyprovider.PROVIDER_TYPE_AVP, integration2.Opts.Info.Name, "Type is avp")
	assert.Equal(suite.T(), keybytes, integration2.Opts.Info.Key, "Keybytes matches for integration 2")

	cmd3 := "add gcp testgcp --file=./test/gcp_test.json"
	res3, err := suite.executeCommand(cmd3, 1)
	assert.NoError(suite.T(), err, "Check no error after add gcp --file")
	testLog.Println(string(res3))

	// Negative tests
	cmds := []string{
		"add avp test3 --keyid=123",
		"add avp test4 --file=./test/testcred.json --keyid=123",
		"add avp test5 --file=notvalid.txt",
		"add gcp test6 --file=notvalid.txt",
	}
	for _, testCmd := range cmds {
		result, err := suite.executeCommand(testCmd, 1)
		assert.Error(suite.T(), err)
		if len(result) > 0 {
			assert.Contains(suite.T(), string(result), "error:")
		}
	}

}

func getPapIds(suite *testSuite) []string {
	integration := suite.pd.cli.Data.GetIntegration("test")
	apps := integration.Apps
	res := []string{}
	for k := range apps {
		res = append(res, k)
	}
	return res
}

func (suite *testSuite) Test2_GetPaps() {
	command := "get paps test"
	testLog.Println("Executing: " + command)
	res, err := suite.executeCommand(command, 1)
	assert.NoError(suite.T(), err, "Check no error for get paps test")
	assert.NotNil(suite.T(), res, "Check result returned")
	testLog.Println(string(res))

	papIds := getPapIds(suite)
	assert.Equal(suite.T(), 1, len(papIds), "should only be 1")

	command = "get paps fail"
	testLog.Println("Executing: " + command)
	res, err = suite.executeCommand(command, 1)
	assert.Error(suite.T(), err, "alias fail not found")
	assert.Empty(suite.T(), res, "Empty result")
}

func (suite *testSuite) Test3_ListIntegrations() {
	command := "show integration test"
	testLog.Println("Executing: " + command)
	res, err := suite.executeCommand(command, 1)
	assert.NoError(suite.T(), err, "Check no error for list integrations test")
	assert.NotEmpty(suite.T(), res, "Check result returned")
	testLog.Println(string(res))

	command = "show integration"
	testLog.Println("Executing: " + command)
	res, err = suite.executeCommand(command, 1)
	assert.NoError(suite.T(), err, "Check no error for list integrations test")
	assert.NotEmpty(suite.T(), res, "Check result returned")

	command = "show integration *"
	testLog.Println("Executing: " + command)
	res, err = suite.executeCommand(command, 1)
	assert.NoError(suite.T(), err, "Check no error for list integrations test")
	assert.NotEmpty(suite.T(), res, "Check result returned")

	command = "show integration fail"
	testLog.Println("Executing: " + command)
	res, err = suite.executeCommand(command, 1)
	assert.Error(suite.T(), err, "alias fail not found")
	assert.Empty(suite.T(), res, "Check empty result returned")

}

func (suite *testSuite) Test4_GetPolicy() {
	// Load up test policies
	integration := suite.pd.cli.Data.GetIntegration("test")
	assert.NotNil(suite.T(), integration)

	papAliases := getPapIds(suite)
	assert.GreaterOrEqual(suite.T(), len(papAliases), 1)
	policyOut := fmt.Sprintf("%s/policytest1-%s.json", suite.testDir, papAliases[0])

	provider := integration.GetProvider()
	mockProvider := provider.(*test.MockProvider)
	testPols, err := hexapolicysupport.ParsePolicyFile("./test/example_idql.json")
	assert.NoError(suite.T(), err, "Check no errors reading test policies")
	assert.Equal(suite.T(), 4, len(testPols))

	appInfo := integration.Apps[papAliases[0]]
	stat, err := mockProvider.SetPolicyInfo(mockProvider.Info, appInfo, testPols)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 200, stat)

	command := fmt.Sprintf("get policies %s -o %s", papAliases[0], policyOut)
	testLog.Println("Executing:\n" + command)

	res, err := suite.executeCommand(command, 1)
	assert.NoError(suite.T(), err, "Check no error on get policies")
	assert.Greater(suite.T(), len(res), 0, "check result returned")
	polBytes, err := os.ReadFile(policyOut)
	assert.NoError(suite.T(), err, "output file could be read")

	testPols2, err := hexapolicysupport.ParsePolicies(polBytes)
	assert.Equal(suite.T(), len(testPols), len(testPols2), "Check same count of policies")
}

func (suite *testSuite) Test5_SetPolicies() {
	// Note: this test assumes policies were loaded from Test1
	papAliases := getPapIds(suite)
	policyPath := fmt.Sprintf("%s/policytest1-%s.json", suite.testDir, papAliases[0])

	testPolicies, err := hexapolicysupport.ParsePolicyFile(policyPath)
	assert.NoError(suite.T(), err, "check no error parsing policies from step 1")

	// Delete the first policy
	testPolicyMods := testPolicies[1:]

	// 2nd policy has a different action
	policy := testPolicyMods[0]
	newAction := hexapolicy.ActionInfo{ActionUri: "http:POST:/update"}
	testPolicyMods[0].Actions = append(policy.Actions, newAction)

	// 3rd policy has a different subject
	testPolicyMods[1].Subject.Members = testPolicyMods[1].Subject.Members[1:]

	// 4th policy unchanged.

	newPolicyPath := fmt.Sprintf("%s/policytest2-%s.json", suite.testDir, papAliases[0])
	difPath := fmt.Sprintf("%s/policydif-%s.json", suite.testDir, papAliases[0])
	policyBytes, err := json.Marshal(&testPolicyMods)
	assert.NoError(suite.T(), err)
	err = os.WriteFile(newPolicyPath, policyBytes, 0660)
	assert.NoError(suite.T(), err)

	// negative tests

	badCommand := fmt.Sprintf("set policies %s -d -f %s -o %s", "notexist", newPolicyPath, difPath)
	testLog.Println("Executing:\n" + badCommand)
	res, err := suite.executeCommand(badCommand, 2)
	assert.Error(suite.T(), err, "pap alias notexist not found\"")

	// positive test
	command := fmt.Sprintf("set policies %s -d -f %s -o %s", papAliases[0], newPolicyPath, difPath)
	testLog.Println("Executing:\n" + command)

	res, err = suite.executeCommand(command, 2)
	assert.NoError(suite.T(), err, "Check no error on set policies")
	assert.Greater(suite.T(), len(res), 0, "check result returned")

	var difs []hexapolicy.PolicyDif
	difBytes, err := os.ReadFile(difPath)
	assert.NoError(suite.T(), err)
	err = json.Unmarshal(difBytes, &difs)
	assert.NoError(suite.T(), err, "Check that difs was parsable")

	newCnt := 0
	updateCnt := 0
	deleteCnt := 0
	matchCnt := 0
	ignoreCnt := 0
	for _, dif := range difs {
		switch dif.Type {
		case hexapolicy.ChangeTypeNew:
			newCnt++
		case hexapolicy.ChangeTypeUpdate:
			updateCnt++
		case hexapolicy.ChangeTypeEqual:
			matchCnt++
		case hexapolicy.ChangeTypeDelete:
			deleteCnt++
		case hexapolicy.ChangeTypeIgnore:
			ignoreCnt++
		default:
			assert.Fail(suite.T(), "Unknown difference type: "+dif.Type)
		}
	}
	assert.Equal(suite.T(), 1, deleteCnt, "Should be 1 delete")
	assert.Equal(suite.T(), 1, matchCnt, "should be 1 match")
	assert.Equal(suite.T(), 2, updateCnt, "should be 2 updates")
	assert.Equal(suite.T(), 0, newCnt, "Should be no new policies")
	assert.Equal(suite.T(), 0, ignoreCnt, "no ignored records")
}

func (suite *testSuite) Test6_Reconcile() {
	integration := suite.pd.cli.Data.GetIntegration("test")
	assert.NotNil(suite.T(), integration)

	// This uses output from previous test
	papAliases := getPapIds(suite)
	policyOrig := fmt.Sprintf("%s/policytest1-%s.json", suite.testDir, papAliases[0])
	newPolicyPath := fmt.Sprintf("%s/policytest2-%s.json", suite.testDir, papAliases[0])
	outputFile := fmt.Sprintf("%s/policytest6-rec.json", suite.testDir)
	command := fmt.Sprintf("reconcile %s %s --output %s", policyOrig, newPolicyPath, outputFile)

	res, err := suite.executeCommand(command, 2)
	assert.NoError(suite.T(), err, "Check no error on reconcile")
	assert.Greater(suite.T(), len(res), 0, "check result returned")

	var difs []hexapolicy.PolicyDif
	difBytes, err := os.ReadFile(outputFile)
	assert.NoError(suite.T(), err)
	err = json.Unmarshal(difBytes, &difs)
	assert.Len(suite.T(), difs, 4, "Should be 4 difs")

	// test that differences works
	command2 := fmt.Sprintf("reconcile %s %s -d --output %s", policyOrig, newPolicyPath, outputFile)

	res, err = suite.executeCommand(command2, 2)
	assert.NoError(suite.T(), err, "Check no error on reconcile")
	assert.Greater(suite.T(), len(res), 0, "check result returned")

	var difs2 []hexapolicy.PolicyDif
	difBytes, err = os.ReadFile(outputFile)
	assert.NoError(suite.T(), err)
	err = json.Unmarshal(difBytes, &difs2)
	assert.Len(suite.T(), difs2, 3, "Should be 3 difs")

	// test against alias first param
	command3 := fmt.Sprintf("reconcile %s %s --output %s", papAliases[0], newPolicyPath, outputFile)

	res, err = suite.executeCommand(command3, 2)
	assert.NoError(suite.T(), err, "Check no error on reconcile")
	assert.Greater(suite.T(), len(res), 0, "check result returned")

	var difs3 []hexapolicy.PolicyDif
	difBytes, err = os.ReadFile(outputFile)
	assert.NoError(suite.T(), err)
	err = json.Unmarshal(difBytes, &difs3)
	assert.Len(suite.T(), difs3, 3, "Should be 3 difs")

	// test against alias first param
	command4 := fmt.Sprintf("reconcile %s %s --output %s", newPolicyPath, papAliases[0], outputFile)

	res, err = suite.executeCommand(command4, 2)
	assert.NoError(suite.T(), err, "Check no error on reconcile")
	assert.Greater(suite.T(), len(res), 0, "check result returned")

	var difs4 []hexapolicy.PolicyDif
	difBytes, err = os.ReadFile(outputFile)
	assert.NoError(suite.T(), err)
	err = json.Unmarshal(difBytes, &difs4)
	assert.Len(suite.T(), difs4, 3, "Should be 3 difs")
}

func (suite *testSuite) Test7_MapToCmd() {
	command := "map to abc"
	_, err := suite.executeCommand(command, 0)

	assert.Error(suite.T(), err, "hexa: error: expected \"<file>\"")

	command = "map to abc ../../examples/policyExamples/idqlAlice.json"
	res, err := suite.executeCommand(command, 0)
	assert.Error(suite.T(), err, fmt.Sprintf("Invalid format. Valid values are: %v", MapFormats))
	assert.Nil(suite.T(), res, "Should be no display text")

	command = "map to cedar ../../examples/policyExamples/idqlAlice.json"
	res, err = suite.executeCommand(command, 0)
	assert.NoError(suite.T(), err, "Should be successful map of cedar")
	assert.Contains(suite.T(), string(res), "permit (")

	command = "map to gcp ../../examples/policyExamples/idqlAlice.json"
	res, err = suite.executeCommand(command, 0)
	assert.NoError(suite.T(), err, "Should be successful map of gcp")
	assert.Contains(suite.T(), string(res), "bindings")
}

func (suite *testSuite) Test8_MapFromCmd() {
	command := "map from abc"
	_, err := suite.executeCommand(command, 0)

	assert.Error(suite.T(), err, "hexa: error: expected \"<file>\"")

	command = "map from abc ../../examples/policyExamples/cedarAlice.txt"
	res, err := suite.executeCommand(command, 0)
	assert.Error(suite.T(), err, fmt.Sprintf("Invalid format. Valid values are: %v", MapFormats))
	assert.Nil(suite.T(), res, "Should be no display text")

	command = "map from cedar ../../examples/policyExamples/cedarAlice.txt"
	res, err = suite.executeCommand(command, 0)
	assert.NoError(suite.T(), err, "Should be successful map of cedar")
	assert.Contains(suite.T(), string(res), "cedar:Photo:")

	command = "map from gcp ../../examples/policyExamples/example_bindings.json"
	res, err = suite.executeCommand(command, 0)
	assert.NoError(suite.T(), err, "Should be successful map of gcp")
	assert.Contains(suite.T(), string(res), "req.ip sw 127 and req.method eq ")
}

func (suite *testSuite) Test99_ConfigSave() {

	config := suite.pd.cli.Data
	assert.NotNil(suite.T(), config, "Check config is not nil")

	err := config.Save(&suite.pd.cli.Globals)
	assert.NoError(suite.T(), err, "Check no error on save")

	info, err := os.Stat(suite.pd.cli.ConfigFile)
	assert.NoError(suite.T(), err, "No error reading config stats")
	assert.Greater(suite.T(), info.Size(), int64(5), "Check data is stored")

	// try re-load
	err = suite.pd.cli.Data.Load(&suite.pd.cli.Globals)
	assert.NoError(suite.T(), err)

	assert.Equal(suite.T(), len(config.Integrations), len(suite.pd.cli.Data.Integrations), "Same size after reload")
}
