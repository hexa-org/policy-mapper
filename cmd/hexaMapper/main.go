package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	policysupport "policy-mapper/policySupport"
	"policy-mapper/policySupport/providers/awsCedar"
	"policy-mapper/policySupport/providers/gcpBind"
	"strings"
)

var helpFlag bool
var revFlag bool
var output string
var input string
var target string
var helpText = `
Hexa tools command line mapping utility. By default, the input is mapped to the target platform. If -p or -parse is specified
the input is mapped from the target platform to IDQL form.

hexaMapper -t=<awsCedar|gcpBind> [-parse] [-o=<output>] <input>

-h -help           Display this text
-t -target=<value> Target platform:  awsCedar, gcpBind
-p -parse          Parse platform to IDQL 
-o -output=<file>  Outputs the results to the specified path, Default is stdout.
`

func main() {
	isForward := true
	flag.BoolVar(&helpFlag, "help", false, "Help information")
	flag.BoolVar(&helpFlag, "h", false, "Help information")
	flag.BoolVar(&revFlag, "p", false, "Map platform policy to IDQL")
	flag.BoolVar(&revFlag, "parse", false, "Map platform policy to IDQL")
	flag.StringVar(&output, "o", "", "Output path, default console")
	flag.StringVar(&output, "output", "", "Output path, default console")
	flag.StringVar(&target, "t", "", "Platform awsCedar|gcpBind")
	flag.StringVar(&target, "target", "", "Platform awsCedar|gcpBind")

	flag.Parse()

	input = flag.Arg(0)
	fmt.Println("Input=\t" + input)
	if helpFlag || target == "" || input == "" {
		if target == "" {
			fmt.Println("Error: Please provide a mapping platform target with the -t parameter.")
		}
		if input == "" {
			fmt.Println("Error: No input source specified.")
		}
		fmt.Printf(helpText)
		return
	}
	if revFlag {
		isForward = false
	}

	if isForward {
		idqlToPlatform(input)
	} else {
		platformToIdql(input)
	}
}

func reportError(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func idqlToPlatform(input string) {
	fmt.Println("Idql to " + target + " requested")

	policies, err := policysupport.ParsePolicyFile(input)
	if err != nil {
		reportError(err)
	}

	switch strings.ToLower(target) {
	case "gcpbind":
		gcpMapper := gcpBind.New(map[string]string{})
		bindings := gcpMapper.MapPoliciesToBindings(policies)
		MarshalJsonNoEscape(bindings, getOutput())

	case "awscedar":
		cMapper := awsCedar.New(map[string]string{})

		cedar, err := cMapper.MapPoliciesToCedar(policies)
		if err != nil {
			reportError(err)
		}
		out := getOutput()
		for _, v := range cedar.Policies {
			policy := v.String()
			out.Write([]byte(policy))
		}
	}
}

func platformToIdql(input string) {
	fmt.Println(target + " to IDQL requested")

	switch strings.ToLower(target) {
	case "gcpbind":
		gcpMapper := gcpBind.New(map[string]string{})
		assignments, err := gcpBind.ParseFile(input)
		if err != nil {
			reportError(err)
		}
		policies, err := gcpMapper.MapBindingAssignmentsToPolicy(assignments)
		if err != nil {
			reportError(err)
		}
		MarshalJsonNoEscape(policies, getOutput())

	case "awscedar":
		cMapper := awsCedar.New(map[string]string{})

		policies, err := cMapper.ParseFile(input)
		if err != nil {
			reportError(err)
		}
		MarshalJsonNoEscape(policies, getOutput())
	}
}

func getOutput() io.Writer {
	if output != "" {
		out, err := os.Create(output)
		if err != nil {
			reportError(err)
		}
		return out
	} else {
		return os.Stdout
	}
}

func MarshalJsonNoEscape(t interface{}, out io.Writer) error {

	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(t)
	return err
}
