# Hexa Policy Mapper Project

This beta project provides the ability to map and support IDQL access policy to and from platforms that support a policy language format.

The goal of this package is to provide a simple way to take policies of different forms, parse them, map them and produce
the translated from. This package uses [IDQL Policy](https://github.com/hexa-org/policy/blob/main/specs/IDQL-core-specification.md) as the neutral representation format.


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
git clone https://github.com/hexa-org/policy-mapper.git
cd policy-mapper
go mod download
go mod tidy
```

See [here](cmd/hexaMapper/ReadMe.md) more instructions on how to run the hexaMapper command line utility.

## Using Hexa-Mapper in Go Projects

### Parsing IDQL

To parse a file, or stream of bytes, use the `policySupport.ParsePolicyFile` or `policySupport.ParsePolicies` functions
to return an array of `[]policySupport.PolicyInfo` objects.  The parser will except either a JSON array of policy objects
or an attribute "policies" which is assigned an array of policies. For example:
```json
{
  "policies": [
    {
      "Meta": {
        "Version": "0.5"
      },
      "Actions": [
        {
          "ActionUri": "cedar:Action::\"view\""
        }
      ],
      "Subject": {
        "Members": [
          "User:\"alice\""
        ]
      },
      "Object": {
        "resource_id": "cedar:Photo::\"VacationPhoto94.jpg\""
      }
    }
  ]
}
```


The follow shows parsing IDQL JSON into `PolicyInfo` objects:

```go
package main

import (
	"fmt"
	policysupport "policy-mapper/policySupport"
)

func main() {
	input := "examples/example_idql.json"
	policies, err := policysupport.ParsePolicyFile(input)
	if (err != nil) {
		fmt.Println(err.Error())
	}
	
	// ...
}
```

### Mapping to a Platform

When mapping to and from a platform, the mapper
will translate attribute names based on a map provided at instantiation.  For example `username` translates to `account.userid` in Google Bind policy.
The when an attribute name map is provided, only attributes listed in the map are translated. All other attribute names are passed unchanged.

To policy from a platform (e.g. Google Bind), instantiate the mapper by providing
a map of strings which indicates IDQL names to platform names. 

```go
    gcpMapper := gcpBind.New(map[string]string{
        "username": "account.userid",
    })
    assignments, err := gcpBind.ParseFile(input)
    if err != nil {
        reportError(err)
    }
    policies, err := gcpMapper.MapBindingAssignmentsToPolicy(assignments)
    if err != nil {
        reportError(err)
    }
```

### Mapping from a Platform

The following shows an example of mapping Cedar Policy to IDQL

```go
    cedarMapper := awsCedar.New(map[string]string{})

    idqlPolicies, err := cedarMapper.ParseFile(input)
    if err != nil {
        reportError(err)
    }
```