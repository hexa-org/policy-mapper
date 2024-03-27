![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Azure Graph Provider

The Azure Provider is a virtual policy provider that processes `Application Roles` from [Application Registration](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps#assign-users-and-groups-to-roles) into 
IDQL policy. In this mapping IDQL `actionUri` is mapped to the Role value (which than appears in tokens received by the application). The
IDQL `resource_id` is the API Name in the Azure portal. Role assignments is extracted from the Enterprise Application User and Groups panels which is returned in the IDQL `members` field.


| Feature           | Description                                                                                                | Platform Support   | Provider Support |
|-------------------|------------------------------------------------------------------------------------------------------------|--------------------|------------------|
| RBAC              | Support for basic translation of role-based access policy                                                  | Yes                | Yes              |
| ABAC              | Support for attribute conditions                                                                           | No                 | No               |
| Type              | Roles are converting into IDQL Policy equivalents                                                          | Azure Applications | Virtual RBAC     |
| Attribute Mapping | Attribute names in policy can be mapped to platform                                                        |                    | N/A              |
| Hexa CLI      | Supported in the Hexa CLI application                                                                  |                    | Yes              |
| Discovery         | Supports discovery of Policy Application Points                                                            | Lists Azure Apps   | Yes              |
| Get Policies      | Supports retrieval of all policies from a PAP                                                              | Conversion         | Yes              |
| Set Policies      | Supports the ability to apply a set of policies to a PAP                                                   | Conversion         | Yes              |
| Reconcile         | Returns the differences between an existing set of policies (e.g. at the source) and another set (updates) |                    | virtual          |

## Policy Support Notes

The following is an example Application returned from Azure (`hexa get apps`):
```text
 PAP Alias: RXK
    ObjectId:   	e136458a-c1e8-4eb8-90fe-f116e8cb4376
    Name:       	canarybankapi
    Description:	9ea71a1d-f0f4-4174-bc2b-7cd3324390a5
    Service:    	App Service
```

The following is an example IDQL mapped Policy from Azure:

```json
{
  "meta": {
    "version": "0.6",
    "sourceData": {
      "enabled": "true",
      "membertypes": [
        "User"
      ]
    },
    "description": "Allows GET /humanresources/us",
    "policyId": "6d77cc79-d09e-427b-a56e-18de918d40cb",
    "papId": "canarybankapi",
    "providerType": "azure"
  },
  "subject": {
    "members": [
      "user:gerry@strata.io",
      "user:saagarwal@gmail.com"
    ]
  },
  "actions": [
    {
      "actionUri": "Read.HR_US"
    }
  ],
  "object": {
    "resource_id": "canarybankapi"
  }
}
```

Notes:
* In the JSON meta attribute, the following values are found:
  * `policyId` - corresponds to `azad.AzureAppRole.ID` the identifier of the Role
  * `description` - is the descriptive text from the Role
  * `papId` - corresponds to the descriptive name of the application
  * `sourceData` - provides Azure specific data such as
    * `enabled` - whether the policy is currently enabled
    * `membertypes` - which indicates whether the application supports `Application` and/or `User` types
* When roles are unassigned, the IDQL `members` attribute returns as an empty array
  
Limitations:
* Condition clauses cannot be mapped (RBAC support only)

