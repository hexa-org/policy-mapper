# Hexa Policy Conditions Support Project

The Hexa Policy Conditions support project provides support for IDQL Policy Conditions (see 
[IDQL Specification section 4.7](https://github.com/hexa-org/policy/blob/main/specs/IDQL-core-specification.md#47-condition)) 
intended for use by [Hexa Policy Orchestrator](https://github.com/hexa-org/policy-orchestrator).

IDQL is a "tuple" based policy language which has 5 key components to a policy rule
which allows most Policy systems such as ABAC, RBAC, Zanzibar, Cedar and OPA to be
mappable from IDQL. In addition to `subject`, `actions`, `object` of policy, the `conditions`
component allows policies to have a conditional component (eg. such as with ABAC). A
condition, is a run-time matching condition that can be applied in addition to courser
matches for subjects (e.g. roles), actions (permissions), and objects (targets).

For example, a condition may be applied that tests the type of authentication of a subject and request parameters.
```
"condition": {
  "rule": "subject.type eq \"Bearer+JWT\" and (subject.roles co privateBanking or subject.roles co prestige)",
  "action": "allow"
},
```
In the above example condition, `subject.type` contains the authorization type for the user (e.g. Anonymous, Bearer+JWT, basic),
and subject.roles are the parsed roles available in a JWT token. Note that for OPA integration, the OpaInput module pre-processes authorization
information. This avoids repeat token validation and decryption within Rego policy processing when evaluating multiple IDQL
policies that are being processed per request.  Note: that in high-risk cases, the token itself can be validated within
rego by processing the claim req.header.authorization using built-in Rego functions.


## Using Policy Conditions

To use this mapper. instantiate a mapper for a particular provider and use the MapConditionToProvider and
MapProviderToCondition to translate in either direction.

Policy-conditions currently supports two target platforms providing bi-directional support: Google Conditional Expression Language
and Open Policy Authorization Rego Hexa integration.


## Google CEL Provider Support
Google CEL condition support converts and IDQL condition expression to CEL and back.  For example, the rule

`subject.common_name eq "google.com" and (subject.country_code eq "US" or subject.country_code eq "IR")`

becomes:

`subject.common_name == "google.com" && (subject.country_code == "US" || subject.country_code == "IR")`

The Google CEL mapper also supports attribute name mapping when instantiating the mapper.  The keys in the map
represent the IDQL values and the values represent the Google CEL attributes. For example, `req.sub` maps to `userid` in the
example below.  Note that attributes not defined in the configuration are passed through as is. Attribute names
are case-insensitive.

A code example:
```go
import (
	"github.com/hexa-org/policySupport/conditions"
    "github.com/hexa-org/policySupport/conditions/googleCel"
)

func main() {
    mapper = GoogleConditionMapper{
        NameMapper: conditions.NewNameMapper(map[string]string{
        "a":        "b",
        "req.sub": "userid",
        }),
    }
	
	idqlCondition := conditions.ConditionInfo{
		Rule: "subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or subject.country_code eq \"IR\")",
		Action: "allow",
    }
	
	// Map to Google CEL Language
	celString, err := mapper.MapConditionToProvider(idqlCondition)
	
	// Convert a CEL expression back into an IDQL Condition
	condition, err := mapper.MapProviderToCondition(celString)
	
	/*
	 Note that in the above code, idqlCondition.Rule should be logically equivalent to condition.Rule. Some differences
	 may occur due to case normalization, removal of unnecessary parentheses, etc.
	*/
}
```

## OPA Integration

The OPA Integration extends the current Policy Orchestrator with new functionality for conditions expressions
support. This integration includes:
* Condition block definition (`/policySupport/conditions/conditions.go`)
* Rego enhancements to add condition expression testing (see below)
* hexaFilter plugin which evaluates an IDQL condition filter against provided input (see below)

_Note:  the current Policy Orchestrator and opaTools integration is slightly out of sync with this project (I am using an 
older version).  The relevant notes here are to aid with integration with the current Policy-Orchestrator project!!_

## Extending OPA Server
To build the new version of OPA with the hexaPlugin included perform the following:
```bash
cd cmd/opa
go build -o hexaOpa

# to start, run like a normal opa server except with the new image:
./hexaOne run --server --config-file config.yaml
```

## OPA Client Integration and Example IDQL
The `hexaFilter` evaluates input structures provided by `client/opa/opaTools` request builder using
a condition clause in IDQL in the Hexa Rego script.  

Exmple IDQL with Condition Statement:
```json
    {
      "id": "TestIPMaskCanaryPOST",
      "meta": {
        "version": "0.1",
        "date": "2021-08-01 21:32:44 UTC",
        "description": "Access enabling user self service for users with role",
        "applicationId": "CanaryBank1",
        "layer": "Browser"
      },
      "subject": {
        "type": "net",
        "providerId": "myTestIDP",
        "cidr" : "127.0.0.1/24"
      },
      "actions": [
        {
          "name": "createProfileIP",
          "actionUri": "ietf:http:POST:/testpath*"
        },
        { "name": "editProfileIP",
          "actionUri": "ietf:http:PUT:/testpath*",
          "exclude": true
        },
        { "name": "getProfileIP",
          "actionUri": "ietf:http:GET:/testpath*"
        }
      ],
      "condition": {
        "rule": "req.ip sw 127 and req.method eq POST",
        "action": "allow"
      },
      "object": {
        "assetId": "CanaryProfileService",
        "pathSpec": "/testpath*"
      }
    }
```

The relevant enhancement in the above IDQL is:
```json
{
  "condition": {
    "rule": "req.ip sw 127 and req.method eq POST",
    "action": "allow"
  }
}
```
In this condition, the input values `req.ip` is evaluated to start with `127` and the `req.method` must equal `POST`.
Note that this example is a bit hypothetical since the "actions" already test permissible actions using the actionURI. The exmaple
provided is mainly to demonstrate that multiple conditions can be tested with and and or clauses as per the 
[IDQL specification.](https://github.com/hexa-org/policy/blob/main/specs/IDQL-core-specification.md)

## Hexa Rego Enhancment
The Hexa IDQL Rego may be enhanced to invoike the Conditions plugin with the following code:
```rego
# Returns the list of matching policy names based on current request
<other code>
allowSet[name] {
    some i
    subjectMatch(policies[i].subject)
    subjectMembersMatch(policies[i].subject)
    subjectRoleMatch(policies[i].subject)
    actionsMatch(policies[i].actions)
    objectMatch(policies[i].object)
    conditionMatch(policies[i])
    policies[i].id
    name := policies[i].id  # this will be id of the policy
}
<...>
conditionMatch(policy) {
    not policy.condition  # Most policies won't have a condition
}

conditionMatch(policy) {
    policy.condition
    policy.condition.rule
    hexaFilter(policy.condition.rule,input)  # HexaFilter evaluations the rule for a match against input
}
<...>

In the above **rego**, the first conditionMatch block allows a rule to proceed if no condition is specified. If a condition value is 
specified, the second block invokes `hexaFilter(policy.condition.rule,input)`  which provides
the available request input in json form. The plugin checks the condition expression against the input for a match.

Note that the current implementation ignores the "action" phrase of the condition which could be allow / deny / audit.  
allow is the default, deny inverts the policy rule (to deny an action). Audit is used in some systems to simply "log" the rule pass/failure
for testing purposes.  IDDQL implementations currently do not use this but it is included for compatibility with platforms like Azure.


