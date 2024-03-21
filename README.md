![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Hexa Policy Mapper Project

The Hexa Policy-Mapper Project provides administrative tools and development libraries for provisioning and mapping 
various policy systems into a common policy format known as [IDQL](https://github.com/hexa-org/policy/blob/main/specs/IDQL-core-specification.md). With Policy Mapper and IDQL, you can manage 
all your access policies consistently across software providers and cloud systems. The project includes a number of 
prebuilt integrations (we call them providers) as well as guidance on how to build your own providers.

This project provides:
* a GoLang SDK which can be used in open source and commercial implementations to leverage this community library.
* a Hexa console command line tool which can be used to provision policies to web accessible policy systems.
* a GoLang interface ([policyprovider.Provider](/api/policyprovider/platform_interface.go)) enabling the development of new policy provisioning providers.

> [!Tip]
> [Policy-Orchestrator](https://github.com/hexa-org/policy-orchestrator) is available as a sample web server implementation that uses Policy-Mapper.

> [!Note]
> This project is currently under initial development and documentation may be out of date.

## Supported Provider Integrations

Policy Mapper supports the following capabilities:

Syntactical Mapping
: Policy formats that have a parsable format or language, and can be represented in a "tuple" (subject, action, resource, conditions, scope) are considered "syntactical". Policy-Mapper can map these formats to and from IDQL JSON format. Examples include: IDQL, Cedar, GCP Bind among others.

RBAC API Mapping
: Some systems do not directly have a policy language but support role or group based access control settings through an API.

Policy Provisioning
: Policy Mapper combines a set of Providers that call APIs to retrieve and map access policy as well as be able to set policy.

Syntactical Mapping support is provided for:
* Google Bind Policy and Google Conditional Expression Language (CEL)
* AWS Verified Permissions and Cedar policy language including support for CEL

Provisioning support is provided for:
* Google [Policy for IAP Secured Resources](https://cloud.google.com/iap/docs/managing-access) (Application Engine and Compute Engine)
* [Amazon Verified Permissions](https://aws.amazon.com/verified-permissions/)
* [OPA Open Policy Agent with Extensions to Support IDQL](https://github.com/hexa-org/policy-opa) and an OPA Extension Plugin to support ABAC policy (conditions) processing
* Provisioning to RBAC based policy systems including (to be ported from hexa-org/policy-orchestrator):
  * Amazon
    * [Cognito RBAC](https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html)
    * [API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-integrate-with-cognito.html)
  * Microsoft Azure

  
## Getting Started

### Installation

Install [go 1.21](https://go.dev), clone and build the project as follows:

```shell
git clone https://github.com/hexa-org/policy-mapper.git

cd policy-mapper

sh ./build.sh
```
## Hexa Console Tool

To test the Hexa SDK and or develop using scripts, use the [Hexa console tool](docs/HexaAdmin.md).

To run the hexa console, simply type `hexa` at the command line once installed.

> [!Note]
> Hexa console currently does not support filenames with spaces. Valid example: add gcp --file=my_key.json

## Hexa Developer Documentation

To start using the Hexa Mapper SDK in your GoLang project, perform the following get command:
```shell
go get github.com/hexa-org/policy-mapper
```
For more details on how to map or provision policy in either console (shell) form or GoLang, see: [Developer documentation](docs/Developer.md).

## Provider Documentation

Each provider in the `providers` directory structure has its own `README.md` that describes the provider and its capabilities and limitations.

| Provider                                                                 | Folder                            | Description                                                                                                                           | Type             | Support     |
|--------------------------------------------------------------------------|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|------------------|-------------|
| [AWS AVP](providers/aws/avpProvider/README.md)                           | providers/aws/avpProvider         | Mapping to/from Cedar Policy language with Get/Set/Reconcile using AVP API                                                            | Syntactic Map    | SDK,Console |
| [AWS API Gateway](providers/aws/awsapigwProvider/README.md)              | providers/aws/awsapigwProvider    | Support for the Amazon API Gateway (**_experimental_**)                                                                               | RBAC             | SDK,Console |
| [AWS Cognito](providers/aws/cognitoProvider/README.md)                   | providers/aws/cognitoProvider     | Virtual policy support using Cognito Userpools and Groups                                                                             | RBAC             | SDK,Console |
| [Azure Provider](providers/azure/azureProvider/README.md)                | providers/azure/azureProvider     | Support for Azure Application Role Policy                                                                                             | RBAC             | SDK,Console |
| [Google Cloud IAP Provider](providers/googlecloud/iapProvider/README.md) | providers\googlecloud\iapProvider | Mapping to/from Google Bind policy and IAP support for Google App Engine and GKE                                                      | Syntactic Map    | SDK,Console |
| [Open Policy Agent](providers/openpolicyagent/README.md)                 | providers/openpolicyagent         | Integrates with [Hexa Policy-OPA](https://github.com/hexa-org/policy-opa) and interprets IDQL directly with conditions clause support | IDQL Interpreter | SDK,Console |



