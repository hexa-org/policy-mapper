
<img src="hexa-boomer.png" title="Boomer" width=75 alt="Hexa-Admin" align="right"/>

# Hexa Developer Documentation

## Provisioning

Hexa Policy Mapper supports the ability to retrieve or set policy from web accessible management APIs. 

### Defining an Integration
An integration is defined simply as a selected provider type and a credential used to access the API. Depending
on the service provider, the information needed may consist of information such as a project identifier, a security key, 
and other information. For example, the Amazon integration key file looks like:

```json
{
  "accessKeyID": "aws-access-key-id",
  "secretAccessKey": "aws-secret-access-key",
  "region": "aws-region"
}
```

<details>
<summary>Hexa Console</summary>

To add an integration in the hexa console, use the `add` command.

```shell
% hexa add <platform> --file=<integrationfile>
```

Here an avp integration is added using a credential file (shown above) called awscred.txt:
```shell
% hexa
hexa> add avp --file=awscred.txt

Integration of type: avp, alias: uAz successfully defined
Succesfully loaded 1 policy application(s) from uAz

Integration: uAz
================
  Type:         avp

  PAP Alias: shK
    ObjectId:           K21RFtX...A93DH7z5
    Name:               arn:aws:verifiedpermissions::7737....1856:policy-store/K21RFtX...A93DH7z5
    Description:        My Policy App
    Service:            VerifiedPermissions

hexa>
```
</details>

<details>
<summary>GoLang</summary>
The following example code opens the integration and loads the defined Policy Application Points and prints them out.

```go
package main

import (
    "encoding/json"
    "fmt"
    "os"

    "github.com/hexa-org/policy-mapper/api/policyprovider"
    "github.com/hexa-org/policy-mapper/sdk"
)

func main() {
    keybytes, err := os.ReadFile("awscred.txt")
    if err != nil {
        panic(-1)
    }

    info := policyprovider.IntegrationInfo{
        Name: sdk.ProviderTypeAvp,
        Key:  keybytes,
    }

    integration, err := sdk.OpenIntegration(&info)
    if err != nil {
        fmt.Println("Error opening integration: " + err.Error())
        panic(-1)
    }

    apps, err := integration.GetPolicyApplicationPoints(nil)
    if err != nil {
        panic(-1)
    }

    for _, app := range apps {
        jsonBytes, _ := json.MarshalIndent(app, "", "  ")
        fmt.Println(string(jsonBytes))
    }

}
```
</details>

### Getting Policy From a Provider Integration

Hexa Get Policies invokes the provider to call to the policy application point to obtain the remote policy and translate it into IDQL.

<details>
<summary>Hexa Console</summary>

To retrieve policies from a PAP, use the `get policies` command. Optionally, use the --output flag to direct output to a file rather than the console.
```shell
hexa get policies <alias/objectid> [--output=policies.idql]
```

For example:
```shell
hexa> get policies shK
Policies retrieved for shK:
{
  "policies": [
    {
      "Meta": {
        "Version": "0.6",
        "SourceData": {
          "policyType": "STATIC",
          "principal": null,
          "resource": null
        },
        "Description": "Hexa demo canary policy",
        "Created": "2023-12-26T21:45:53.558204Z",
        "Modified": "2023-12-27T22:20:18.592795Z",
        "Etag": "20-68c071fc33494d8d27b460fdae42aa1211025c24",
        "PolicyId": "KDqUKMRNEg6aEjZ6mz9dJq",
        "PapId": "K21RFtX...A93DH7z5",
        "ProviderType": "avp"
      },
      "Subject": {
        "Members": [
          "any"
        ]
      },
      "Actions": [
        {
          "ActionUri": "cedar:hexa_avp::Action::\"ReadAccount\""
        },
        {
          "ActionUri": "cedar:hexa_avp::Action::\"Transfer\""
        },
        {
          "ActionUri": "cedar:hexa_avp::Action::\"Deposit\""
        },
        {
          "ActionUri": "cedar:hexa_avp::Action::\"Withdrawl\""
        },
        {
          "ActionUri": "cedar:hexa_avp::Action::\"UpdateAccount\""
        }
      ],
      "Object": {
        "resource_id": ""
      }
    },
    {
      "Meta": {
        "Version": "0.6",
        "SourceData": {
          "policyType": "TEMPLATE_LINKED",
          "principal": {
            "EntityId": "gerry@strata.io",
            "EntityType": "hexa_avp::User"
          },
          "resource": {
            "EntityId": "1",
            "EntityType": "hexa_avp::account"
          }
        },
        "Description": "TestTemplate",
        "Created": "2023-11-23T19:18:16.470806Z",
        "Modified": "2023-11-23T19:18:16.470806Z",
        "Etag": "20-c7411b365c2d202b19d981a11eacf37bed72e52d",
        "PolicyId": "UaN2xdjgv1Dhdpuoa3ebRU",
        "PapId": "K21RFtX...A93DH7z5",
        "ProviderType": "avp"
      },
      "Subject": {
        "Members": [
          "?principal"
        ]
      },
      "Actions": [
        {
          "ActionUri": "cedar:hexa_avp::Action::\"ReadAccount\""
        }
      ],
      "Object": {
        "resource_id": "cedar:?resource"
      }
    }
  ],
  "app": "K21RFtX...A93DH7z5"
}
hexa>  

```

</details>

<details>
<summary>Go Lang</summary>
Once an integration is opened, the `Integration.GetPolicies` function can be used to retrieve policies as a `hexapolicy.Policies` structure.

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/sdk"
)

func main() {
	. . . <open integration> . . .

	apps, err := integration.GetPolicyApplicationPoints(nil)
	if err != nil {
		panic(-1)
	}

	for _, app := range apps {

		fmt.Println("PAP " + app.ObjectID)

		policies, err := integration.GetPolicies(app.ObjectID)
		if err != nil {
			fmt.Println("Error retrieving policies: " + err.Error())
		}
		jsonBytes, _ := json.MarshalIndent(policies, "", "  ")
		fmt.Println("IDQL returned:")
		fmt.Println(string(jsonBytes))
	}
}
```
</details>

### Setting Policies

Once an integration is defined, Hexa can set policies by taking input IDQL policies, mapping to the target platform and sending to the update API.
In some cases (e.g. Amazon AVP), the existing policies are matched (e.g. using meta information or comparison) and the necessary update operations are calculated as part of the update.

<details>
<summary>Hexa Console</summary>

The Hexa console `set policies` command is of the form
```shell
set policies <alias|objectid> [-d] --file=<idqlpolicies.json>
```
If the `-d` option is set, the console will show the planned differences and ask for confirmation before proceeding. This output is the same 
as for the `reconcile` command.

```shell
hexa> set policies rKO -d --file=policies.json

Ignoring AVP policyid UaN2xdjgv1Dhdpuoa3ebRU. Template updates not currently supported
0: DIF: UPDATE  [ACTION]
{
 "Meta": {
  "Version": "0.6",
  "SourceData": {
   "policyType": "STATIC",
   "principal": null,
   "resource": null
  },
  "Description": "Hexa demo canary policy",
  "Created": "2023-12-26T21:45:53.558204Z",
  "Modified": "2023-12-27T22:20:18.592795Z",
  "Etag": "20-f2ec1edc53e44c07e4d790d8936ade24b27f04eb",
  "PolicyId": "KDqUKMRNEg6aEjZ6mz9dJq",
  "PapId": "K21...93DH7z5",
  "ProviderType": "avp"
 },
 "Subject": {
  "Members": [
   "any"
  ]
 },
 "Actions": [
  {
   "ActionUri": "cedar:hexa_avp::Action::\"ReadAccount\""
  },
  {
   "ActionUri": "cedar:hexa_avp::Action::\"Transfer\""
  },
  {
   "ActionUri": "cedar:hexa_avp::Action::\"Deposit\""
  },
  {
   "ActionUri": "cedar:hexa_avp::Action::\"Withdrawl\""
  }
 ],
 "Object": {
  "resource_id": ""
 }
}
1: DIF: UNSUPPORTED 
{
 "Meta": {
  "Version": "0.6",
  "SourceData": {
   "policyType": "TEMPLATE_LINKED",
   "principal": {
    "EntityId": "gerry@strata.io",
    "EntityType": "hexa_avp::User"
   },
   "resource": {
    "EntityId": "1",
    "EntityType": "hexa_avp::account"
   }
  },
  "Description": "TestTemplate",
  "Created": "2023-11-23T19:18:16.470806Z",
  "Modified": "2023-11-23T19:18:16.470806Z",
  "Etag": "W/\"20-c7411b365c2d202b19d981a11eacf37bed72e52d\"",
  "PolicyId": "UaN2xdjgv1Dhdpuoa3ebRU",
  "PapId": "K21...93DH7z5",
  "ProviderType": "avp"
 },
 "Subject": {
  "Members": [
   "?principal"
  ]
 },
 "Actions": [
  {
   "ActionUri": "cedar:hexa_avp::Action::\"ReadAccount\""
  }
 ],
 "Object": {
  "resource_id": "cedar:?resource"
 }
}

Applying 2 policies to rKO
Update policies Y|[n]?
```

</details>

<details>
<summary>Go Lang</summary>

```go
package main

import (
	"fmt"
	"os"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
	"github.com/hexa-org/policy-mapper/sdk"
)

func main() {
	keybytes, err := os.ReadFile("awscred.txt")
	if err != nil {
		panic(-1)
	}

	info := policyprovider.IntegrationInfo{
		Name: sdk.ProviderTypeAvp,
		Key:  keybytes,
	}

	integration, err := sdk.OpenIntegration(&info)
	if err != nil {
		fmt.Println("Error opening integration: " + err.Error())
		panic(-1)
	}
	
	hexaPolicies, err := hexapolicysupport.ParsePolicyFile("idqlinput.json")

	status, err := integration.SetPolicyInfo("<alias>",hexaPolicies)
}
```

</details>

## Syntactical Policy Mapping

Hexa-Mapper provides a few utility packages to parse IDQL, GCP Bind, and Amazon Cedar policy languages.

### Parsing IDQL

To parse a file or stream of bytes, use the `hexapolicysupport.ParsePolicyFile` or `hexapolicySupport.ParsePolicies` functions
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
    "github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
)

func main() {
    input := "examples/example_idql.json"
    idqlPolicies, err := hexapolicysupport.ParsePolicyFile(input)
    if (err != nil) {
        fmt.Println(err.Error())
    }

    // ...
}
```

### Mapping Between IDQL and Platforms

When mapping to and from a platform, the mapper
will translate attribute names based on a map provided at instantiation.  For example `username` translates to `account.userid` in Google Bind policy.
The when an attribute name map is provided, only attributes listed in the map are translated. All other attribute names are passed unchanged.

#### Mapping to and From GCP
Mapping functions support converting GCP Bind policy in JSON format to and from IDQL JSON form. This includes
conversion of GCP Common Expression Language (CEL) to IDQL conditions.

<details>
<summary>Hexa Console</summary>

To map files in the hexa console, use the `map to` or `map from` commands as follows:

```shell
% hexa map to gcp input.idql gcpout.json
% hexa map from gcp gcpin.json output.idql
```

To map from or to a policy application source, use the PAP object id or local alias in place of a file name:

```shell
% hexa map to gcp input.idql <alias|objectid>
% hexa map from gcp <alias|objectid> output.idql
```
</details>

<details>
<summary>Go Lang</summary>
Instantiate the gcpBind mapper (`github.com/hexa-org/policy-mapper/models/formats/gcpBind`)by providing
a map of strings which indicates IDQL names to platform names.

```go
package main

import (
    "github.com/hexa-org/policy-mapper/models/formats/gcpBind"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
)

func main() {

    input := "examples/example_idql.json"
    idqlPolicies, err := hexapolicysupport.ParsePolicyFile(input)
    if (err != nil) {
        fmt.Println(err.Error())
    }
    
    // instantiate gcp mapper with attribute translation for username to account.userid
    gcpMapper := gcpBind.New(map[string]string{
        "username": "account.userid",
    })
    
    // obtain the GCP Binding assignments from IDQL
    bindAssignments :=  gcpMapper.MapPoliciesToBindings(idqlPolicies)
    
    // Convert GCP Bind Assignments back into IDQL
    idqlPoliciesAgain, err := gcpMapper.MapBindingAssignmentsToPolicy(bindAssignments)
    if err != nil {
        fmt.Println(err.Error())
    }
}
```
</details>

### Mapping to and from Amazon Verified Permissions Cedar

Mapping functions support converting Amazon Cedar policy to and from IDQL JSON form. This includes
conversion of Cedar Conditions to IDQL Conditions.

<details>
<summary>Hexa Console</summary>

To map files in the hexa console, use the `map to` or `map from` commands as follows:

```shell
hexa map to cedar input.idql cedarout.txt
hexa map from cedar cedarin.txt output.idql
```

To map from or to a policy application source, use the PAP object id or local alias in place of a file name:

```shell
hexa map to cedar input.idql <alias|objectid>
hexa map from cedar <alias|objectid> output.idql
```
</details>

<details>
<summary>Go Lang</summary>
To map from a platform (e.g. Cedar), instantiate the cedar mapper by providing an optional attribute name map, and then call the appropriate parser such as
`ParseFile` or `ParseCedarBytes`.

```go
package main

import (
    "fmt"
    "github.com/hexa-org/policy-mapper/models/formats/awsCedar"
)

func main() {
    cedarMapper := awsCedar.New(map[string]string{})

    input := "mycedarpolicy.txt"

    idqlPolicies, err := cedarMapper.ParseFile(input)
    if err != nil {
        panic(-1)
    }

    // to map back into Cedar
    cedarPolicies, err := cedarMapper.MapPoliciesToCedar(idqlPolicies.Policies)

    ...
}
```

</details>