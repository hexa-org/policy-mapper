# Amazon API Gateway Provider

**_Experimental_**

The API Gateway Provider is a virtual RBAC provider that combines Cognito User Pools and a custom Dynao DB to build RBAC relationships to create equivalent IDQL policy. 

This provider is currently **experimental** and depends on undocumented configuration to run. Please contact gerry@strata.io for more information. 

See: Tutorial: B[uild a CRUD API with Lambda and DynamoDB](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-dynamo-db.html).

| Feature           | Description                                                                                                | Platform Support               | Provider Support |
|-------------------|------------------------------------------------------------------------------------------------------------|--------------------------------|------------------|
| RBAC              | Support for basic translation of role-based access policy                                                  | Yes                            | Yes              |
| ABAC              | Support for attribute conditions                                                                           | No                             | No               |
| Type              | Virtual policy Cognito directory, Dynamo DB for use with Amazon API Gateway                                | Cognito, DynamoDb, API Gateway | Virtual RBAC     |
| Attribute Mapping | Attribute names in policy can be mapped to platform                                                        |                                | N/A              |
| Hexa Console      | Supported in the Hexa Console application                                                                  |                                | Yes              |
| Discovery         | Supports discovery of Policy Application Points                                                            | List UserPools and Resources   | Yes              |
| Get Policies      | Supports retrieval of all policies from a PAP                                                              | Conversion                     | Yes              |
| Set Policies      | Supports the ability to apply a set of policies to a PAP                                                   | Conversion                     | Yes              |
| Reconcile         | Returns the differences between an existing set of policies (e.g. at the source) and another set (updates) |                                | virtual          |

## Policy Support Notes

The following is an example IDQL mapped Policy:

```json
  {
  "meta": {
    "version": "0.6",
    "providerType": "RARmodel"
  },
  "subject": {
    "members": [
      "Read.Profile1",
      "Read.Profile2",
      "Read.Profile3",
      "Read.Profile4"
    ]
  },
  "actions": [
    {
      "actionUri": "http:GET"
    }
  ],
  "object": {
    "resource_id": "/profile"
  }
}
```

DynamoDB Resource Policies Table

| Resource (String)  | Action (String) | Members                                                           |
|--------------------|-----------------|-------------------------------------------------------------------|
| /profile           | GET             | ["Read.Profile1","Read.Profile2","Read.Profile3","Read.Profile4"] |
| /analytics         | GET             | ["Read.Analytics"]                                                |
| /humanresources/eu | GET             | []                                                                |
| /humanresources/uk | GET             | ["Read.HR_UK"]                                                    |
| /humanresources/us | GET             | ["Read.HR_US"]                                                    |
| /developer         | GET             | ["Read.Developer"]                                                |



Limitations:
* Condition clauses cannot be mapped (RBAC only)

