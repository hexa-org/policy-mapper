
<div style="text-align: right; float: left"><img src="hexa-boomer.png" title="Boomer" width=75 alt="Hexa-Admin"/></div>

# Hexa Devleoper Documentation

### Parsing IDQL

To parse a file, or stream of bytes, use the `hexapolicysupport.ParsePolicyFile` or `hexapolicySupport.ParsePolicies` functions
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

The follow shows parsing IDQL JSON into `[]PolicyInfo` objects:

```go
package main

import (
	"fmt"
	policysupport github.com/hexa-org/policy-map/pkg/hexapolicysupport
)

func main() {
	input := "examples/example_idql.json"
	policies, err := hexapolicysupport.ParsePolicyFile(input)
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