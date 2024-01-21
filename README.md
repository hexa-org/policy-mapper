# Hexa Policy Mapper Project

The Hexa Policy-Mapper Project provides administrative tools and development libraries for provisioning and mapping various policy systems into a common policy format known as [IDQL](https://github.com/hexa-org/policy/blob/main/specs/IDQL-core-specification.md).

This project provides:
* a GOLANG SDK which can be used in open source and commercial implementations to leverage this community library.
* a Hexa administration tool which can be used to provision policies to web accessible policy systems
* a common interface (provider) which enables the development of new policy provisioning providers to extend policy-mapper capabilities

> [!Note]
> This project is currently under initial development and documentation may be out of date.

## Supported Provider Integrations

Policy Mapper supports two major areas of functionality:

Syntactical Mapping
: Policy systems that support a defined policy format, can be represented in a "tuple" (subject, action, resource, conditions, scope) are considered "syntactical". Policy-Mapper can map these formats to and from IDQL JSON format.

Policy Provisioning
: Policy Mapper consists of a set of `Provider`s that can retrieve, and map access policy as well as be able to set policy.

Mapping support is provided for:
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
## Hexa Administration Tool

To test the Hexa SDK and or develop using scripts, use the [Hexa command line tool](docs/HexaAdmin.md).

## Hexa Developer Documentation

See: [Developer documentation](docs/Developer.md).

