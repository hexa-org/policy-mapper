# Hexa Policy Mapper Project

This project provides the ability to map and support IDQL access policy into platforms that support their own policy language format.

Currently, mapping support is provided for:

* Google Bind Policy and Google Conditional Expression Language (CEL)
* AWS Verified Permissions and Cedar policy language including support for CEL
* OPA Extensions to Support IDQL and an OPA Extension Plugin to support ABAC policy (conditions) processing

The project is broken into the following parts:
* [Policy Conditions](policySupport/conditions/ReadME.md)
* [IDQL Policy and Policy Mapping](policySupport)
* [OPA Server Extensions ](server/ReadME.md)
* [HexaMapper command line utility](cmd/hexaMapper/ReadMe.md)

## Getting Started

For general introduction to Hexa, please see the [Policy-Orchestrator ReadMe](https://github.com/hexa-org/policy-orchestrator).

### Prerequisites

Install the following dependencies.

- [Go 1.19](https://go.dev)
- Clone the project and run the following in the terminal window:
```shell
git clone https://github.com/hexa-org/policy-conditions.git
cd policy-conditions
go mod download
go mod tidy
```

See [here](cmd/hexaMapper/ReadMe.md) more instructions on how to run the hexaMapper command line utility.

## Using Hexa-Mapper in Go Projects

To be completed.