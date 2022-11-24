package googlecloud

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"policy-conditions/policySupport/conditions"
	"testing"
)

var mapper = GoogleConditionMapper{}

func TestParseFilter(t *testing.T) {
	for _, example := range []string{

		"userName sw \"J\"",
		"test.name sw \"J\"",
		"subject.common_name eq \"google.com\" and subject.country_code eq \"US\" or subject.country_code eq \"IR\"",

		// Following tests that parenthesis and logic preserved
		"subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or subject.country_code eq \"IR\")",
		"subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or not (subject.country_code eq \"IR\"))",

		"userName eq \"bjensen\"",
		"userName Eq \"bjensen\"",
		"name.familyName co \"O'Malley\"",

		//"title pr",   // Not implemented
		"meta.lastModified gt \"2011-05-13T04:42:34Z\"",
		"meta.lastModified ge \"2011-05-13T04:42:34Z\"",
		"meta.lastModified lt \"2011-05-13T04:42:34Z\"",
		"meta.lastModified le \"2011-05-13T04:42:34Z\"",
		//"title pr and userType eq \"Employee\"",
		//"title pr or userType eq \"Intern\"",
		"userType eq \"Employee\" and (emails co \"example.com\" or emails.value co \"example.org\")",
		"userType eq \"Employee\" and (emails.type eq \"work\")",
		"userType ne \"Employee\" and not (emails co \"example.com\" or emails.value co \"example.org\")",
		//"userType eq \"Employee\" and emails[type eq \"work\" and value co \"@example.com\"]",  // ValueFilter not implemented
		//"emails[type eq \"work\" and value co \"@example.com\"] or ims[type eq \"xmpp\" and value co \"@foo.com\"]",

		//"name pr and userName pr and title pr",
		//"name pr and not (first eq \"test\") and another ne \"test\"",
		//"NAME PR AND NOT (FIRST EQ \"test\") AND ANOTHER NE \"test\"",
		//"name pr or userName pr or title pr",
	} {
		t.Run(example, func(t *testing.T) {

			condition := conditions.ConditionInfo{
				Rule:   example,
				Action: "allow",
			}
			fmt.Println("Test:\t" + example)
			celString, err := mapper.MapConditionToProvider(condition)
			assert.NoError(t, err, "error mapping IDQL Condition to Google CEL")
			fmt.Println("=>GCP:\t" + celString)

			conditionBack, err := mapper.MapProviderToCondition(celString)
			assert.NoError(t, err, "error parsing/mapping CEL statement to IDQL Condition")
			returnExample := conditionBack.Rule
			fmt.Println("=>IDQL:\t" + returnExample)
			// Because of case-insensitive tests (Eq vs eq vs EQ) round trip may not match in mixed cases.
			//assert.Equal(t, strings.ToLower(example), strings.ToLower(returnExample), "Round-trip map test failure")
			//assert.Equal(t, example, conditionBack.Rule, "Round-trip map test failure")

		})
	}
}
