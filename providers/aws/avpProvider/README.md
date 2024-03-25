# Amazon Verified Permissions Provider

The Amazon Verified Permissions Provider (AVP) is a [fine-grained permissions management system](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/what-is-avp.html) for customer written applications.
AVP uses an open source policy language known as [Cedar](https://docs.cedarpolicy.com).

The Hexa AVP Provider enables the ability to syntactically transform between policy language formats between IDQL and Cedar. This includes
support for Cedar Conditions.

| Feature           | Description                                                                                                   | Platform Support                                      | Provider Support                           |
|-------------------|---------------------------------------------------------------------------------------------------------------|-------------------------------------------------------|--------------------------------------------|
| RBAC              | Support for basic translation of role-based access policy                                                     | Yes                                                   | Yes                                        |
| ABAC              | Support for attribute conditions                                                                              | Yes                                                   | Yes                                        |
| Type              | Policy is described 'syntactically' in an exportable<BR/>format or implied through 'role' based relationships | Syntactic                                             | Syntactic Mapper                           |
| Attribute Mapping | Attribute names in policy can be mapped to platform                                                           |                                                       | Yes                                        |
| Hexa CLI      | Supported in the Hexa CLI application                                                                     |                                                       | Yes                                        |
| Discovery         | Supports discovery of Policy Application Points                                                               | AVP Instance Discovery                                | Yes                                        |
| Get Policies      | Supports retrieval of all policies from a PAP                                                                 | Yes                                                   | Yes                                        |
| Set Policies      | Supports the ability to apply a set of policies to a PAP                                                      | Yes<BR/>Individual policy CRUD<BR/>Restricted updates | Supported via reconciliation<BR/>into CRUD |
| Reconcile         | Returns the differences between an existing set of policies (e.g. at the source) and another set (updates)    |                                                       | Yes                                        |

## Policy Support Notes

Support includes support for both conversion of IDQL to and from Cedar format.
This GoLang implementation includes an AST parser for both Cedar Policy and the condition expressions (similar to
Google Conditional Expression Language).

The following is an example Cedar policy:
```text
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
permit (
    principal == User::"stacey",
    action == Action::"view",
    resource
)
when { resource in Account::"stacey" };
```

In the above example, there are 2 polcies separated by a semicolon (;). In the second policy a condition is expressed as
`resource in Account::"stacey"`.  The Hexa AVP Provider interprets this policy and transforms into IDQL Json format as shown below:

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
    },
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
          "User:\"stacey\""
        ]
      },
      "Object": {
        "resource_id": ""
      },
      "Condition": {
        "Rule": "resource in \"Account:stacey\"",
        "Action": "permit"
      }
    }
  ]
}
```

Mapping support works by:
* Converting actions and resources into uris where the first element indicates the originating format (e.g. `cedar:`);
* Preserves quotations in original form using escaping (\\");
* The Google CEL AST parser is used to parse Cedar condition expressions (they are the same form)
* Attribute mapping is configurable in the SDK using the `sdk.WithAttributeMap` option.

Limitations:
* Currently Hexa does not support interrogation of platform specific policy schema. This is because in part very few platforms support
  this feature. It should be noted that AVP does support this via the AVP API.  What the mapper does instead is to syntactically convert
  names (e.g. to be JSON format) while leaving the names unchanged.
* Not all condition "functions" can be represented in IDQL's SCIM format. This will be extended in the future.

