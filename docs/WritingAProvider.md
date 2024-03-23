![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Writing A Hexa Provider

Before writing a new provider, check out the [SDK Developer Documentation](Developer.md) and the [Hexa Administration Guide](HexaAdmin.md) to get a 
general understanding of IDQL and how current providers work.

In general every Hexa Provider implements the [policyprovider.Provider](../api/policyprovider/platform_interface.go) interface. 

Current providers use one of 3 different methods for provisioning policies to target platforms:

## Types of Policies Languages and Mappers

### Syntactical Mappers

Syntactical Mapping is where the target system has its own policy language that in essence contain "tuples" of 
information the describe _**Subjects**_ the _**Actions**_ they may take against an _**Object**_ under a set of _**Conditions**_ and _**Scope**_.
Examples of syntactical policy languages include [Google Bind](https://cloud.google.com/iam/docs/reference/rest/v1/Policy) and [Amazon Cedar Policy](https://www.cedarpolicy.com/en).

For syntactical mapping, the technique used by Hexa is to parse the target language into an AST tree, walk the tree translating
each node into the IDQL equivalent. For an example of this, see: the [/models/formats](../models/formats) directory.  

> [!Note]
> Syntactical mappers currently do not have a standardized interface. To see how the existing mappers are used, look at
> the `map` command inside the hexa console [command.go](../cmd/hexa/commands.go).

Example invocation of syntactical mapper:
```go
func (m *MapToCmd) Run(cli *CLI) error {
	fmt.Println(fmt.Sprintf("Mapping IDQL to %s", m.Format))
	policies, err := hexapolicysupport.ParsePolicyFile(m.File)
	if err != nil {
		return err
	}

	switch strings.ToLower(m.Format) {
	case "gcp":
		gcpMapper := gcpBind.New(map[string]string{})  // This map defines attribute name mapping
		bindings := gcpMapper.MapPoliciesToBindings(policies)
		_ = MarshalJsonNoEscape(bindings, os.Stdout)
		outWriter := cli.GetOutputWriter()
		_ = MarshalJsonNoEscape(bindings, outWriter.GetOutput())
		outWriter.Close()
	case "cedar":
		cMapper := awsCedar.New(map[string]string{})  // This map defines attribute name mapping

		cedar, err := cMapper.MapPoliciesToCedar(policies)
		if err != nil {
			return err
		}

		for _, v := range cedar.Policies {
			policy := v.String()
			fmt.Println(policy)
			cli.GetOutputWriter().WriteString(policy, false)
		}
		cli.GetOutputWriter().Close()
	}
	return nil
}
```

### Virtualized RBAC

Virtualized RBAC takes information from a user directory and a set of resources and determines which groups, users may 
use what application or resource roles. The virtualizated RBAC is intended to indicate that policy is achieved through
configuration and administration rather than through a policy specific API.

Examples of this include:
  * [Microsoft Application Roles](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps#assign-users-and-groups-to-roles)
  * [Amazon API Gateway and Dynamo Db](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-dynamo-db.html)

Cognito, API Gateway, Azure, use a common [Resource Action Role](../models/rar) model to convert IDQL into RBAC settings in
each platform. 

### IDQL Interpreted

This is intended to describe systems that can process IDQL directly. One of these is the [Open Policy Agent](https://www.openpolicyagent.org) 
which has its own declarative language "Rego" (eg. like Java or GoLang) that can support complex evaluation constructs. 
In the case of OPA, a [HexaPolicy Rego policy](../examples/opa-server/bundleServer/bundles/bundle/hexaPolicy.rego) is 
used to interpret IDQL policies provided as "data" to the Rego engine.  

## Special Considerations

### Amazon Verified Permissions
Policy Identifiers  Some APIs (e.g. Amazon Verified Permissions) impose complex logic on how to update policies whereas others allow 
simple set and get. For example, updating a policy in AVP requires knowing the policy identifier for the policy and imposes
restrictions on which parts ot the policy may be updated.

### Hexa OPA Provider
The Hexa OPA provider uses policy IDs to allow applications to find out what entitlements a user may have based on their current
authentication context.