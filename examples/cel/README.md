# Example: Mapping Condition Expression Language

The code in [celexample.go](celexample.go) is intended to show how to map from IDQL Condition expressions to a CEL expression in string
form and back again to an IDQL Condition using the packages:
- "github.com/hexa-org/policy-mapper/models/conditionLangs/gcpcel"
- "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"

Note:  
- line 11 instantiates the mapper with a name translation map. In the example attribute "a" in IDQL is translated to "b".  Another example is req.sub to userid.
- line 16 is an IDQL Condition expression that evaluates a hypothetical attribute "subject" that has sub-attributes common_name, and country_code.

CEL is used in policy mapping for both [Google Bind Policy](../../providers/googlecloud/iapProvider/README.md) and Amazon [Cedar Policy](../../providers/aws/avpProvider/README.md) (unofficially).

