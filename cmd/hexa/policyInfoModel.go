package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hexa-org/policy-mapper/models/policyInfoModel"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/pimValidate"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
)

type LoadCmd struct {
	Model LoadModelCmd `cmd:"" help:"load a policy information model"`
}

type LoadModelCmd struct {
	File string `arg:"" required:"" type:"path" help:"A json file containing an IDQL Policy Model or Cedar Schema"`
}

func (m *LoadModelCmd) Run(cli *CLI) error {
	var err error
	modelBytes, err := os.ReadFile(m.File)
	if err != nil {
		return err
	}

	var ns *policyInfoModel.Namespaces
	ns, err = policyInfoModel.ParseSchemaFile(modelBytes)
	if err != nil {
		return err
	}

	if ns == nil {
		return errors.New("No policy model data found in " + m.File)
	}

	if cli.Namespaces == nil {
		cli.Namespaces = ns

	} else {
		dns := *ns
		for key, schema := range dns {
			(*cli.Namespaces)[key] = schema
		}
	}

	fmt.Println("Namespaces loaded:")
	for k, _ := range *ns {
		fmt.Println(fmt.Sprintf("\t%s", k))
	}
	return nil
}

type ShowModelCmd struct {
	Namespace string `arg:"" required:"" help:"The policy application namespace to show (or *)"`
}

func printAttrs(ow *OutputWriter, amap map[string]policyInfoModel.AttrType) {
	if amap == nil || len(amap) == 0 {
		line := "No attributes defined\n\n"
		fmt.Print(line)
		ow.WriteString(line, false)
		return
	}

	var line string
	for key, attr := range amap {
		line = fmt.Sprintf("%-20s\t%s\n", key, attr.Type)
		fmt.Print(line)
		ow.WriteString(line, false)
	}
	fmt.Print("\n")
	ow.WriteString("\n", false)
}

func displayNamespace(ow *OutputWriter, name string, schema policyInfoModel.SchemaType) {
	line := fmt.Sprintf("\nNamespace: %s\n", name)
	divider := strings.Repeat("=", len(line)-2) + "\n\n"
	fmt.Print(line)
	fmt.Print(divider)
	ow.WriteString(line, false)
	ow.WriteString(divider, false)

	fmt.Print("Entities:\n")
	ow.WriteString("Entities\n", false)
	for k, e := range schema.EntityTypes {
		memberof := e.MemberOfTypes
		line := fmt.Sprintf("%s\n", k)
		if memberof != nil || len(memberof) > 0 {
			line = fmt.Sprintf("%s MemberOf: %v\n", k, memberof)
		}
		divider = strings.Repeat("-", len(line)-1) + "\n"
		fmt.Print(line)
		fmt.Print(divider)
		ow.WriteString(line, false)
		ow.WriteString(divider, false)

		attrs := e.Shape.Attributes
		printAttrs(ow, attrs)

	}

	if len(schema.CommonTypes) > 0 {
		fmt.Print("Common Types:\n\n")
		ow.WriteString("Common Types:\n\n", false)
		for k, e := range schema.CommonTypes {
			line := fmt.Sprintf("%s\n", k)
			divider = strings.Repeat("-", len(line)-1) + "\n"
			fmt.Print(line)
			ow.WriteString(line, false)
			fmt.Print(divider)
			ow.WriteString(divider, false)
			attrs := e.Attributes
			printAttrs(ow, attrs)
		}
	} else {
		fmt.Print("\nNo Common Types\n\n")
		ow.WriteString("\nNo Common Types\n\n", false)
	}

	if len(schema.Actions) > 0 {
		fmt.Print("Actions:\n\n")
		ow.WriteString("Actions:\n\n", false)
		for k, e := range schema.Actions {
			memberof := e.MemberOf
			line := fmt.Sprintf("%s, ", k)
			if memberof != nil || len(memberof) > 0 {
				line = fmt.Sprintf("%s, MemberOf: %v, ", k, memberof)
			}
			fmt.Print(line)
			ow.WriteString(line, false)

			line = "applies to\n"
			fmt.Print(line)
			ow.WriteString(line, false)
			if e.AppliesTo.PrincipalTypes != nil {
				types := strings.Join(*e.AppliesTo.PrincipalTypes, ", ")
				line = fmt.Sprintf(" Subjects ->\t%s\n", types)
				fmt.Print(line)
				ow.WriteString(line, false)
			}
			if e.AppliesTo.ResourceTypes != nil {
				types := strings.Join(*e.AppliesTo.ResourceTypes, ", ")
				line = fmt.Sprintf(" Objects ->\t%s\n", types)
				fmt.Print(line)
				ow.WriteString(line, false)
			}
		}
	} else {
		fmt.Print("\nNo Actions\n\n", false)
		ow.WriteString("\nNo Actions\n\n", false)
	}

}

func (s *ShowModelCmd) Run(cli *CLI) error {
	ow := cli.GetOutputWriter()
	if cli.Namespaces == nil {
		return errors.New("no namespaces loaded. Use the `load model` command")
	}
	if s.Namespace == "*" {
		for k, v := range *cli.Namespaces {
			displayNamespace(ow, k, v)
		}
	} else {
		ns, ok := (*cli.Namespaces)[s.Namespace]
		if !ok {
			return errors.New("namespace not found or not loaded")
		}
		displayNamespace(ow, s.Namespace, ns)
	}
	ow.Close()
	return nil
}

type ValidatePolicyCmd struct {
	Namespace string `arg:"" required:"" help:"Default namespace for the policy (e.g. PhotoApp)"`
	File      string `arg:"" required:"" type:"path" help:"A json file containing an IDQL Policy to be validated"`
}

func (v *ValidatePolicyCmd) Run(cli *CLI) error {
	ow := cli.GetOutputWriter()
	if cli.Namespaces == nil {
		return errors.New("no namespaces loaded. Use the `load model` command")
	}
	validator := pimValidate.GetValidator(*cli.Namespaces, v.Namespace)

	policies, err := hexapolicysupport.ParsePolicyFile(v.File)
	if err != nil {
		return err
	}
	if policies == nil || len(policies) == 0 {
		return errors.New("no policies found")
	}

	for i, policy := range policies {
		pid := fmt.Sprintf("Policy-%d", i)
		if policy.Meta.PolicyId != nil {
			pid = *policy.Meta.PolicyId
		}
		fmt.Print(pid)
		ow.WriteString(pid, false)

		validationErrors := validator.ValidatePolicy(policy, i)
		if validationErrors == nil {
			line := "...Valid\n\n"
			fmt.Print(line)
			ow.WriteString(line, false)
			continue

		}
		if len(validationErrors) > 0 {
			line := "...Errors:\n "
			fmt.Print(line)
			ow.WriteString(line, false)
			for _, report := range validationErrors {
				line := fmt.Sprintf("  Element: %s, Value: %s\n", report.ElementName, report.Value)
				fmt.Print(line)
				ow.WriteString(line, false)
				for _, err := range report.Errs {
					line := fmt.Sprintf("  %s\n", err.Error())
					fmt.Print(line)
					ow.WriteString(line, false)
				}

			}
		}

		fmt.Print("\n")
		ow.WriteString("\n", false)
	}
	ow.Close()
	return nil
}

type ValidateCmd struct {
	Policy ValidatePolicyCmd `cmd:"" help:"validate a set of policies against a policy model (previously loaded)"`
}
