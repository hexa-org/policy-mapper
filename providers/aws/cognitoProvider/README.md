# Amazon Cognito Provider

The Cognito Provider is a virtual provider that processes a Cognito User Pool and converts the RBAC relationships defined in the Groups to generate equivalent IDQL policy. The provider
does this by interrogating User Pools and their associated resources. In general, Groups are mapped to IDQL Actions, and Resources are mapped to `resource_id`.


| Feature           | Description                                                                                                   | Platform Support             | Provider Support |
|-------------------|---------------------------------------------------------------------------------------------------------------|------------------------------|------------------|
| RBAC              | Support for basic translation of role-based access policy                                                     | Yes                          | Yes              |
| ABAC              | Support for attribute conditions                                                                              | No                           | No               |
| Type              | Policy is described 'syntactically' in an exportable<BR/>format or implied through 'role' based relationships | Directory Groups             | Virtual RBAC     |
| Attribute Mapping | Attribute names in policy can be mapped to platform                                                           |                              | N/A              |
| Hexa Console      | Supported in the Hexa Console application                                                                     |                              | Yes              |
| Discovery         | Supports discovery of Policy Application Points                                                               | List UserPools and Resources | Yes              |
| Get Policies      | Supports retrieval of all policies from a PAP                                                                 | Conversion                   | Yes              |
| Set Policies      | Supports the ability to apply a set of policies to a PAP                                                      | Conversion                   | Yes              |
| Reconcile         | Returns the differences between an existing set of policies (e.g. at the source) and another set (updates)    |                              | virtual          |

## Policy Support Notes

The following is an example IDQL mapped Policy from Cognito:

```json
{
  "meta": {
    "version": "0.6",
    "providerType": "cognito"
  },
  "subject": {
    "members": [
      "user:saagarwal@gmail.com"
    ]
  },
  "actions": [
    {
      "actionUri": "GET/humanresources/eu"
    }
  ],
  "object": {
    "resource_id": "canarybankapi"
  }
}
```

Limitations:
* Condition clauses cannot be mapped (RBAC only)

