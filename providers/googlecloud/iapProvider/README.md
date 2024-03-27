![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Google IAP Provider

The Google IAP Provider uses the [IDQL to GCP Bind Mapper](../../../models/formats/gcpBind/google_bind_policy.go) to enable syntactical bi-directional conversion of Google Bind Policy to IDQL policy. This includes
support for conversion of Google Condition Expression Language into IDQL's SCIM style conditions.


| Feature           | Description                                                                                                   | Platform Support                           | Provider Support |
|-------------------|---------------------------------------------------------------------------------------------------------------|--------------------------------------------|------------------|
| RBAC              | Support for basic translation of role-based access policy                                                     | Yes                                        | Yes              |
| ABAC              | Support for attribute conditions                                                                              | Yes                                        | Yes              |
| Type              | Policy is described 'syntactically' in an exportable<BR/>format or implied through 'role' based relationships | Syntactic                                  | Syntactic Mapper |
| Attribute Mapping | Attribute names in policy can be mapped to platform                                                           |                                            | Yes              |
| Hexa CLI      | Supported in the Hexa CLI application                                                                     |                                            | Yes              |
| Discovery         | Supports discovery of Policy Application Points                                                               | Queries IAP Backend and AppEngine services | Yes              |
| Get Policies      | Supports retrieval of all policies from a PAP                                                                 | Yes                                        | Yes              |
| Set Policies      | Supports the ability to apply a set of policies to a PAP                                                      | Yes                                        |
| Reconcile         | Returns the differences between an existing set of policies (e.g. at the source) and another set (updates)    |                                            | Yes              |

## Policy Support Notes

Support includes support for both conversion of IDQL to and from [Google Bind Policy](https://cloud.google.com/iam/docs/policies) format. For information on policies supported see
[Managing Access to IAP-Secured Resources](https://cloud.google.com/iap/docs/managing-access#roles).

This provider includes IDQL to Bind Policy transformation and Google Conditional Expression Language to IDQL conditions using an AST translator and configurable attribute name mapper.

The following is an example Bind policy:
```json
 {
  "resource_id": "hexa-411616",
  "bindings": [
    {
      "members": [
        "user:gerry@strata.io",
        "user:independentidentity@gmail.com"
      ],
      "role": "roles/iap.httpsResourceAccessor"
    }
  ]
}

```

The equivalent IDQL Policy is as follows:

```json
{
  "meta": {
    "version": "0.6"
  },
  "subject": {
    "members": [
      "user:gerry@strata.io",
      "user:independentidentity@gmail.com"
    ]
  },
  "actions": [
    {
      "actionUri": "gcp:roles/iap.httpsResourceAccessor"
    }
  ],
  "object": {
    "resource_id": "hexa-411616"
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

