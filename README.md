# Hexa Policy Mapper Project

The Hexa Policy-Mapper Project provides administrative tools and development libraries for provisioning and mapping various policy systems into a common policy format known as [IDQL](https://github.com/hexa-org/policy/blob/main/specs/IDQL-core-specification.md).

This project provides:
* a GOLANG SDK which can be used in open source and commercial implementations to leverage this community library.
* a Hexa console command line tool which can be used to provision policies to web accessible policy systems.
* a GoLang interface (`policyprovider.Provider`) enabling the development of new policy provisioning providers.

> [!Note]
> This project is currently under initial development and documentation may be out of date.

## Supported Provider Integrations

Policy Mapper supports the following capabilities:

Syntactical Mapping
: Policy formats that have a parsable format or language, and can be represented in a "tuple" (subject, action, resource, conditions, scope) are considered "syntactical". Policy-Mapper can map these formats to and from IDQL JSON format. Examples include: IDQL, Cedar, GCP Bind among others.

RBAC API Mapping
: Some systems do not directly have a policy language but support role based access control settings through an API.

Policy Provisioning
: Policy Mapper combines a set of Providers that call APIs to retrieve and map access policy as well as be able to set policy.

Syntactical Mapping support is provided for:
* Google Bind Policy and Google Conditional Expression Language (CEL)
* AWS Verified Permissions and Cedar policy language including support for CEL

Provisioning support is provided for:
* Google Bind Policy (Application Engine and Compute Engine)
* Amazon Verified Permissions
* (coming) OPA Extensions to Support IDQL and an OPA Extension Plugin to support ABAC policy (conditions) processing
* Provisioning to RBAC based policy systems including (to be ported from hexa-org/policy-orchestrator):
  * Amazon
    * Cognito
    * API Gateway
  * Microsoft Azure

  
## Getting Started

### Installation

Install [go 1.21](https://go.dev), clone and build the project as follows:

```shell
git clone https://github.com/hexa-org/policy-mapper.git
sh ./build.sh
```
## Hexa Console Tool

To test the Hexa SDK and or develop using scripts, use the [Hexa console tool](docs/HexaAdmin.md).

To run the hexa console, simply type `hexa` at the command line once installed.

## Hexa Developer Documentation

To start using the Hexa Mapper SDK in your GoLang project, perform the following get command:
```shell
go get github.com/hexa-org/policy-mapper
```
For more details on how to map or provision policy in either console (shell) form or GoLang, see: [Developer documentation](docs/Developer.md).

