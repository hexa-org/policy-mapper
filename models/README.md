![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Models for Translating IDQL Policy

This directory contains models for translating different types of policies that may be used by 1 or more providers or
directly in the Hexa CLI tool.

The `conditionLangs` directory holds AST parsers for other policy languages such as `gcpcel` (Google Condition Expression Language). 
These parsers are meant to work with the IDQL Condition Parser. For an example, see: [examples/cel](../examples/cel/README.md).

The `formats` directory holds parsers for syntactical policies such as [Google Bind](formats/gcpBind), and [Amazon Cedar](formats/awsCedar).
For examples on using these parsers, see the Hexa CLI [commands.go](../cmd/hexa/commands.go), and look for the `MapToCmd` and `MapFromCmd` `Run` functions.

The `rar` directory contains a **_Resource Action Role_** model used by multiple providers that are directory centric. This model
is currently used in the [awsapigwProvider](../providers/aws/awsapigwProvider/README.md) and the azure azarm package which is used by the [azureProvider](../providers/azure/azureProvider/README.md).