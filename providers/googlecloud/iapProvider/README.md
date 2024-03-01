# Google IAP Provider

The Google IAP Provider uses the [IDQL to GCP Bind Mapper](../../../models/formats/gcpBind/google_bind_policy.go) to enable syntactical bi-directional conversion of Google Bind Policy to IDQL policy. This includes
support for conversion of Google Condition Expression Language into IDQL's SCIM style conditions.


| Feature           | Description                                                                                                   | Platform Support                           | Provider Support |
|-------------------|---------------------------------------------------------------------------------------------------------------|--------------------------------------------|------------------|
| RBAC              | Support for basic translation of role-based access policy                                                     | Yes                                        | Yes              |
| ABAC              | Support for attribute conditions                                                                              | Yes                                        | Yes              |
| Type              | Policy is described 'syntactically' in an exportable<BR/>format or implied through 'role' based relationships | Syntactic                                  | Syntactic Mapper |
| Attribute Mapping | Attribute names in policy can be mapped to platform                                                           |                                            | Yes              |
| Hexa Console      | Supported in the Hexa Console application                                                                     |                                            | Yes              |
| Discovery         | Supports discovery of Policy Application Points                                                               | Queries IAP Backend and AppEngine services | Yes              |
| Get Policies      | Supports retrieval of all policies from a PAP                                                                 | Yes                                        | Yes              |
| Set Policies      | Supports the ability to apply a set of policies to a PAP                                                      | Yes                                        |
| Reconcile         | Returns the differences between an existing set of policies (e.g. at the source) and another set (updates)    |                                            | Yes              |

## Policy Support Notes

Support includes support for both conversion of IDQL to and from [Google Bind Policy](https://cloud.google.com/iam/docs/policies) format.
This GoLang implementation includes an AST parser Bind Policy and Google Conditional Expression Language.

The following is an example Bind policy:
```json
 {
  "resource_id": "aResourceId3",
  "bindings": [
    {
      "condition": {
        "expression": "req.ip.startsWith(\"127\") \u0026\u0026 req.method == \"POST\""
      },
      "members": [
        "accounting@hexaindustries.io"
      ]
    }
  ]
}
```

The equivalent IDQL Policy is as follows:

```json
{
  "meta": {"version": "0.6"},
  "actions": [{"action_uri": "http:GET:/accounting"}, {"action_uri": "http:POST:/accounting"}],
  "subject": {
    "members": [
      "accounting@hexaindustries.io"
    ]
  },
  "condition": {
    "rule": "req.ip sw 127 and req.method eq POST",
    "action": "allow"
  },
  "object": {
    "resource_id": "aResourceId3"
  }
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

