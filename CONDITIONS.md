# Hexa Policy Conditions

Hexa Policy Conditions provides support for IDQL Policy Conditions (see
[IDQL Specification section 4.7](https://github.com/hexa-org/policy/blob/main/specs/IDQL-core-specification.md#47-condition))
intended for use by [Hexa Policy Orchestrator](https://github.com/hexa-org/policy-orchestrator).

In addition to `subject`, `actions`, `object` of a typical policy, the `conditions`
component allows policies to have a conditional component (eg. attribute based access control). A
condition, is a run-time matching condition that can be applied in addition to courser
matches for subjects (e.g. roles), actions (permissions), and objects (targets).

For example, an IDQL condition may be applied that tests the type of authentication of a subject and request parameters.
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

Policy-Mapper currently supports two target platforms providing bi-directional support: Google Conditional Expression Language
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
package main

import (
  "fmt"

  "github.com/hexa-org/policy-mapper/mapper/conditionLangs/gcpcel"
  "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
)

func main() {
  mapper := gcpcel.GoogleConditionMapper{NameMapper: conditions.NewNameMapper(map[string]string{
    "a":       "b",
    "req.sub": "userid",
  })}

  idqlCondition := conditions.ConditionInfo{
    Rule:   "subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or subject.country_code eq \"IR\")",
    Action: "allow",
  }

  // Map to Google CEL Language
  celString, err := mapper.MapConditionToProvider(idqlCondition)
  if err != nil {
    fmt.Println(err.Error())
    panic(-1)
  }
  fmt.Println("Mapped Google CEL format: " + celString)

  // Convert a CEL expression back into an IDQL Condition
  condition, err := mapper.MapProviderToCondition(celString)
  if err != nil {
    fmt.Println(err.Error())
    panic(-1)
  }
  fmt.Println(fmt.Sprintf("Mapped IDQL Condition: %v", condition))
}
```

### CEL Mapping Scope of Support
The current scope of support for mapping Google CEL expression is limited to common IAM policy cases.
The following Google CEL functions and operators are currently not support.
* ? Conditional Operators
* size list or map size functions
* type attribute type function and type(null)
* all time functions:
  * getDate, 
  * getDayOfMonth, 
  * getDayOfWeek, 
  * getDayOfYear, 
  * getFullYear, 
  * getHours, 
  * getMilliseconds, 
  * etMinutes, 
  * getMonths, 
  * getSeconds, 
  * duration
* regex functions such as matches

## OPA Condition Integration

See [OPA Plugin Readme](../../server/ReadME.md).
