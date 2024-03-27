![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Example: Using the SDK To Read Polcies from AVP

The GoLang code in [exampleIntegration.go](exampleIntegration.go) shows how to open an integration using the Hexa-Mapper SDK.
In this example, a credential file for AWS is read in and an integration is opened. The application then calls 
`GetPolicyApplicationPoints` to discover the defined AVP integrations. It then calls `GetPolicies` and `SetPolicies` to retrieve
and set policies GoLang.

In this example, the retrieved policies are formatted in a hexaPolicy.Policies structure.

For more information on the contents of the Amazon credential file, use the Hexa CLI as follows:

```shell
hexa help add avp
```

See the AVP Provider [README](../../providers/aws/avpProvider/README.md) for more information.

See the [developer guide](../../docs/Developer.md) for more information on use of the SDK integration.