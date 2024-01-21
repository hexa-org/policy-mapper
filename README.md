# Hexa Policy Mapper Project

The Hexa Policy-Mapper Project provides an sdk for provisioning and mapping various policy systems into a common policy format known as [IDQL](https://github.com/hexa-org/policy/blob/main/specs/IDQL-core-specification.md).

This project provides:
* a GOLANG SDK which can be used in open source and commercial implementations to leverage this community library.
* a Hexa administration tool which can be used to provision policies to web accessible policy systems
* a common interface (provider) which enables the development of new policy provisioning providers to extend policy-mapper capabilities

> [!Note]
> This project is currently under initial development and documentation may be out of date._**

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

### Prerequisites

Install the following dependencies.

- [go 1.21](https://go.dev)
- Clone the project and run the following in the terminal window:
```shell
git clone https://github.com/hexa-org/policy-mapper.git
sh ./build.sh
```

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
        "Version": "0.6"
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
	policysupport github.com/hexa-org/policy-map/pkg/hexapolicysupport
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