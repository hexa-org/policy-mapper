package googleCel

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"policy-conditions/policySupport/conditions"
	"testing"
)

var mapper = GoogleConditionMapper{
	NameMapper: conditions.NewNameMapper(map[string]string{
		"a":        "b",
		"c":        "d",
		"username": "account.userid",
	}),
}

func TestParseFilter(t *testing.T) {
	examples := [][2]string{
		{
			"principal.numberOfLaptops lt 5 and principal.joblevel gt 6",
			"principal.numberOfLaptops lt 5 and principal.joblevel gt 6",
		},
		{"account.active eq true", "account.active eq true"},
		// Note: PR only works for compound attributes like account.userid in Google
		{"username pr", "username pr"},

		{"userName sw \"J\"", "username sw \"J\""},
		{"test.name sw \"J\"", "test.name sw \"J\""},
		{
			"username eq \"june\" or username eq fred or username eq alice",
			"username eq \"june\" or username eq \"fred\" or username eq \"alice\"",
		},
		{
			"username eq \"june\" and username eq fred and username eq alice",
			"username eq \"june\" and username eq \"fred\" and username eq \"alice\"",
		},
		{
			"subject.common_name eq \"google.com\" and subject.country_code eq \"US\" or subject.country_code eq \"IR\"",
			"subject.common_name eq \"google.com\" and subject.country_code eq \"US\" or subject.country_code eq \"IR\"",
		}, {
			"subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or subject.country_code eq \"IR\")",
			"subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or subject.country_code eq \"IR\")",
		},

		// Following tests that parenthesis and logic preserved
		{
			"subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or subject.country_code eq \"IR\")",
			"subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or subject.country_code eq \"IR\")",
		}, {
			"subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or not (subject.country_code eq \"IR\"))",
			"subject.common_name eq \"google.com\" and (subject.country_code eq \"US\" or not(subject.country_code eq \"IR\"))",
		}, {
			"userName eq \"bjensen\"", "username eq \"bjensen\"",
		}, {
			"userName Eq \"bjensen\"", "username eq \"bjensen\"",
		}, { // this should not correct case because name.familityName not in attribute name list
			"name.familyName co \"O'Malley\"", "name.familyName co \"O'Malley\"",
		},

		// Following tests confirm > < >= <=
		{"meta.lastModified gt \"2011-05-13T04:42:34Z\"", "meta.lastModified gt \"2011-05-13T04:42:34Z\""},
		{"meta.lastModified ge \"2011-05-13T04:42:34Z\"", "meta.lastModified ge \"2011-05-13T04:42:34Z\""},
		{"meta.lastModified lt \"2011-05-13T04:42:34Z\"", "meta.lastModified lt \"2011-05-13T04:42:34Z\""},
		{"meta.lastModified le \"2011-05-13T04:42:34Z\"", "meta.lastModified le \"2011-05-13T04:42:34Z\""},
		{"username pr and userType eq \"Employee\"", "username pr and userType eq \"Employee\""},
		{"username pr or userType eq \"Intern\"", "username pr or userType eq \"Intern\""},

		{
			"userType eq \"Employee\" and (emails co \"example.com\" or emails.value co \"example.org\")",
			"userType eq \"Employee\" and (emails co \"example.com\" or emails.value co \"example.org\")",
		},
		{
			"userType eq \"Employee\" and (emails.type eq \"work\")",
			"userType eq \"Employee\" and emails.type eq \"work\"",
		},
		{
			// Confirms proper handling of not brackets
			"userType ne \"Employee\" and not (emails co \"example.com\" or emails.value co \"example.org\")",
			"userType ne \"Employee\" and not(emails co \"example.com\" or emails.value co \"example.org\")",
		},
		//"userType eq \"Employee\" and emails[type eq \"work\" and value co \"@example.com\"]",  // ValueFilter not implemented
		//"emails[type eq \"work\" and value co \"@example.com\"] or ims[type eq \"xmpp\" and value co \"@foo.com\"]",

	}
	for _, example := range examples {
		t.Run(example[0], func(t *testing.T) {

			condition := conditions.ConditionInfo{
				Rule:   example[0],
				Action: "allow",
			}
			fmt.Println("Test:\t" + example[0])
			celString, err := mapper.MapConditionToProvider(condition)
			assert.NoError(t, err, "error mapping IDQL Condition to Google CEL")
			fmt.Println("=>GCP:\t" + celString)

			conditionBack, err := mapper.MapProviderToCondition(celString)
			assert.NoError(t, err, "error parsing/mapping CEL statement to IDQL Condition")
			returnExample := conditionBack.Rule
			fmt.Println("=>IDQL:\t" + returnExample)

			assert.Equal(t, example[1], returnExample, "Check expected result matches: &s", example[1])
			// Because of case-insensitive tests (Eq vs eq vs EQ) round trip may not match in mixed cases.
			//assert.Equal(t, strings.ToLower(example), strings.ToLower(returnExample), "Round-trip map test failure")
			//assert.Equal(t, example, conditionBack.Rule, "Round-trip map test failure")

		})
	}
}
