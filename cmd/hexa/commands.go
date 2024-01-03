// This code based on contributions from https://github.com/i2-open/i2goSignals with permission
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/alecthomas/kong"
	"github.com/hexa-org/policy-mapper/api/PolicyProvider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
	"github.com/hexa-org/policy-mapper/sdk"
)

var seperatorline = "==============================================================================="

type GcpIntegration struct {
	// TODO To be implemented
}

type AvpIntegration struct {
	Alias  string  `arg:"" optional:"" help:"A new local alias that will be used to refer to the integration in subsequent operations. Defaults to an auto-generated alias"`
	Region *string `short:"r" required:"" help:"The Amazon data center (e.g. us-west-1)"`
	Keyid  *string `short:"k" required:"" help:"Amazon Access Key ID"`
	Secret *string `short:"s" required:"" help:"Secret access key"`
	File   []byte  `short:"f" xor:"Keyid" required:"" type:"filecontent" help:"File containing the amazon credential information"`
}

func (a *AvpIntegration) AfterApply(_ *kong.Context) error {
	if a.File == nil {
		if a.Secret == nil || a.Keyid == nil || a.Region == nil {
			return errors.New("must provide all of --keyid, --secret, and --region, or --file")
		}
	} else {
		if len(a.File) == 0 {
			return errors.New("file was empty or not found")
		}
		if a.Secret != nil || a.Keyid != nil || a.Region != nil {
			return errors.New("must provide all of --keyid, --secret, and --region, or --file")
		}
	}

	return nil
}

func (a *AvpIntegration) Run(cli *CLI) error {
	alias := a.Alias
	if alias == "" {
		alias = generateAliasOfSize(3)

	}

	if cli.Data.GetIntegration(alias) != nil {
		errMsg := fmt.Sprintf("Alias \"%s\" exists", alias)
		if !ConfirmProceed(errMsg + ", overwrite Y[n]") {
			return errors.New(errMsg)
		}
	}
	keyStr := a.File

	if len(keyStr) == 0 {
		keyStr = []byte(fmt.Sprintf(`{
  "accessKeyID": "%s",
  "secretAccessKey": "%s",
  "region": "%s"
}`, *a.Keyid, *a.Secret, *a.Region))
	}
	info := PolicyProvider.IntegrationInfo{
		Name: PolicyProvider.PROVIDER_TYPE_AVP,
		Key:  []byte(keyStr),
	}
	integration, err := sdk.OpenIntegration(nil, sdk.WithIntegrationInfo(info))
	if err != nil {
		return err
	}

	integration.Alias = alias
	fmt.Println(fmt.Sprintf("Integration of type: %s, alias: %s successfully defined", integration.GetType(), alias))

	_, err = integration.GetPolicyApplicationPoints(func() string {
		return generateAliasOfSize(3)
	})
	if err != nil {
		return err
	}

	appMap := integration.Apps
	appCount := len(appMap)
	if appCount == 0 {
		fmt.Println("No policy applications discovered.")
		return nil
	}
	fmt.Printf("Successfully loaded %v policy application(s) from %s\n", appCount, alias)
	if appCount > 0 {
		printIntegrationApps(integration)
	}
	// printer.Print(appMap)
	cli.Data.Integrations[alias] = integration
	err = cli.Data.Save(&cli.Globals)
	return err
}

type AddCmd struct {
	Avp AvpIntegration `cmd:"" aliases:"cedar" help:"Add an Amazon Verified Permissions integration"`
	Gcp GcpIntegration `cmd:"" help:"Add a Google Cloud GCP integration"`
}

type GetPolicyApplicationsCmd struct {
	Alias string `arg:"" required:"" help:"Alias for a previously defined integration to retrieve from"`
}

func (a *GetPolicyApplicationsCmd) Run(cli *CLI) error {
	integration := cli.Data.GetIntegration(a.Alias)
	if integration == nil {
		return errors.New(fmt.Sprintf("alias %s not found", a.Alias))
	}

	_, err := integration.GetPolicyApplicationPoints(func() string {
		return generateAliasOfSize(3)
	})
	if err != nil {
		return err
	}

	if len(integration.Apps) == 0 {
		fmt.Println("No policy applications discovered.")
		return nil
	}

	printIntegrationApps(integration)

	return nil
}

type GetPoliciesCmd struct {
	Alias string `arg:"" required:"" help:"Alias for a Policy Application Point to retrieve policies from"`
}

func (a *GetPoliciesCmd) Run(cli *CLI) error {
	integration, app := cli.Data.GetApplicationInfo(a.Alias)
	if app == nil {
		return errors.New(fmt.Sprintf("pap alias %s not found", a.Alias))
	}

	policies, err := integration.GetPolicies(a.Alias)
	if err != nil {
		return err
	}

	fmt.Println(fmt.Sprintf("Policies retrieved for %s:", a.Alias))

	output, _ := json.MarshalIndent(policies, "", "  ")
	cli.GetOutputWriter().WriteBytes(output, true)
	fmt.Println(fmt.Sprintf("%s", output))
	return nil
}

type GetCmd struct {
	Paps     GetPolicyApplicationsCmd `cmd:"" aliases:"apps" help:"Retrieve or discover policy application points from the specified integration alias"`
	Policies GetPoliciesCmd           `cmd:"" aliases:"pol" help:"Get and map policies from a PAP."`
}

type SetPoliciesCmd struct {
	Alias       string `arg:"" required:"" help:"The alias of a PAP (application) where policies are to be set/reconciled with the provided policies"`
	File        string `short:"f" required:"" type:"path" help:"A file containing IDQL policy to be applied (REQUIRED)"`
	Differences bool   `optional:"" default:"false" short:"d" help:"When specified, the list of changes to be applied will be shown before confirming change (if supported by provider)"`
}

func (s *SetPoliciesCmd) Run(cli *CLI) error {
	integration, app := cli.Data.GetApplicationInfo(s.Alias)
	if app == nil {
		return errors.New(fmt.Sprintf("pap alias %s not found", s.Alias))
	}

	policies, err := hexapolicysupport.ParsePolicyFile(s.File)
	if err != nil {
		return err
	}

	if s.Differences {
		diffs, err := integration.ReconcilePolicy(s.Alias, policies, false)
		if errors.Is(err, errors.New("provider does not support reconcile")) {
			fmt.Println("Integration provider does not support reconcile.")
		} else {
			for i, diff := range diffs {
				fmt.Println(fmt.Sprintf("%d: %s", i, diff.Report()))
			}
			fmt.Println()
			// Write to output if specified
			output, _ := json.MarshalIndent(diffs, "", "  ")
			cli.GetOutputWriter().WriteBytes(output, true)
		}
	}

	msg := fmt.Sprintf("Applying %d policies to %s", len(policies), s.Alias)
	fmt.Println(msg)
	if ConfirmProceed("Update policies Y|[n]?") {

		res, err := integration.SetPolicyInfo(s.Alias, policies)
		if err != nil {
			return err
		}
		switch res {
		case http.StatusAccepted, http.StatusOK:
			fmt.Println("Policies applied successfully.")
		case http.StatusBadRequest, http.StatusInternalServerError:
			fmt.Println("Bad request or internal processing error")
		case http.StatusUnauthorized, http.StatusForbidden:
			fmt.Println("Request was unauthorized or forbidden")
		default:
			fmt.Println(fmt.Sprintf("Received HTTP Status: %d", res))
		}
	}
	return nil
}

type SetCmd struct {
	Policies SetPoliciesCmd `cmd:"" aliases:"pol,policy" help:"Set policies at a policy application point"`
}

type ShowIntegrationCmd struct {
	Alias string `arg:"" optional:"" help:"An alias for an integration or * to list all. Defaults to listing all"`
}

func printIntegrationInfo(integration *sdk.Integration) {
	title := fmt.Sprintf("Integration: %s", integration.Alias)
	fmt.Println(title)

	fmt.Println(seperatorline[0:len(title)])
	fmt.Println("  Type:   \t" + integration.GetType())
	printIntegrationApps(integration)

}

func (l *ShowIntegrationCmd) Run(cli *CLI) error {
	if l.Alias == "*" || l.Alias == "" {
		if len(cli.Data.Integrations) == 0 {
			fmt.Println("No integrations defined. See 'add' command.")
			return nil
		}
		for _, v := range cli.Data.Integrations {
			printIntegrationInfo(v)
			fmt.Println()
		}
		return nil
	}
	integration := cli.Data.GetIntegration(l.Alias)
	if integration == nil {
		return errors.New(fmt.Sprintf("alias %s not found", l.Alias))
	}
	fmt.Println("Policy Application Points retrieved:")
	fmt.Println()
	printIntegrationApps(integration)
	return nil
}

type ListAppCmd struct {
	Alias string `arg:"" required:"" help:"The alias of an application or integration whose applications are to be listed."`
}

func printApplication(key string, app PolicyProvider.ApplicationInfo) {
	fmt.Printf("  PAP Alias: %s\n", key)
	fmt.Printf("    ObjectId:   \t%s\n", app.ObjectID)
	fmt.Printf("    Name:       \t%s\n", app.Name)
	fmt.Printf("    Description:\t%s\n", app.Description)
	fmt.Printf("    Service:    \t%s\n", app.Service)
}

func printIntegrationApps(integration *sdk.Integration) {

	for k, app := range integration.Apps {
		fmt.Println()
		printApplication(k, app)
	}
}

func (l *ListAppCmd) Run(cli *CLI) error {
	alias := l.Alias
	integration := cli.Data.GetIntegration(alias)
	if integration != nil {
		fmt.Println("Listing applications for integration " + alias + ":")
		printIntegrationApps(integration)
	} else {
		_, app := cli.Data.GetApplicationInfo(alias)
		if app == nil {
			return errors.New("alias " + alias + " not found")
		}
		printApplication(alias, *app)
	}
	return nil
}

type ShowCmd struct {
	Integration ShowIntegrationCmd `cmd:"" aliases:"int,i" help:"Show locally defined information about a provider integration"`
	Pap         ListAppCmd         `cmd:"" aliases:"app,p,a" help:"Show locally stored information about a policy application"`
}

func ConfirmProceed(msg string) bool {
	if msg != "" {
		fmt.Print(msg)
	} else {
		fmt.Print("Proceed Y|[n]? ")
	}

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	if line[0:1] == "Y" {
		return true
	}
	return false
}

type ExitCmd struct {
}

func (e *ExitCmd) Run(globals *Globals) error {
	err := globals.Data.Save(globals)
	if err != nil {
		fmt.Println(err.Error())
		if ConfirmProceed("Abort exit? Y|[n] ") {
			return nil
		}
	}
	os.Exit(-1)
	return nil
}

type HelpCmd struct {
	Command []string `arg:"" optional:"" help:"Show help on command."`
}

// Run shows help.
func (h *HelpCmd) Run(realCtx *kong.Context) error {
	ctx, err := kong.Trace(realCtx.Kong, h.Command)
	if err != nil {
		return err
	}
	if ctx.Error != nil {
		return ctx.Error
	}
	// fmt.Printf("Args:\t%v\n", ctx.Args)
	// fmt.Printf("Command:\t%s\n", ctx.Command())
	err = ctx.PrintUsage(false)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(realCtx.Stdout)
	return nil
}
