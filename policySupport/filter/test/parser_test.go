package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"policy-conditions/policySupport/filter"
	"testing"
)

func TestParseFilter(t *testing.T) {
	examples := [][2]string{
		{"title pr"},
		{"name pr and userName pr and title pr"},
		{"name.familyName co \"O'Malley\""},
		{"userName eq \"bjensen\""},
		{"level gt 12"},
		{"level gt 12.3"},
		{"level eq 123.45e-5"},
		{"userName Eq \"bjensen\"", "userName eq \"bjensen\""},
		{"userName eq A or username eq \"B\" or username eq C", "userName eq \"A\" or username eq \"B\" or username eq \"C\""},

		{"userName sw \"J\""},
		{"urn:ietf:params:scim:schemas:core:2.0:User:userName sw \"J\""},

		{"meta.lastModified gt \"2011-05-13T04:42:34Z\""},
		{"meta.lastModified ge \"2011-05-13T04:42:34Z\""},
		{"meta.lastModified lt \"2011-05-13T04:42:34Z\""},
		{"meta.lastModified le \"2011-05-13T04:42:34Z\""},
		{"title pr and userType eq \"Employee\""},
		{"title pr or userType eq \"Intern\""},
		{"schemas eq \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\""},

		{"userType eq \"Employee\" and (emails.type eq \"work\")"},
		{"userType eq \"Employee\" and emails[type eq \"work\" and value co \"@example.com\"]"},
		{"userType eq \"Employee\" and (emails co \"example.com\" or emails.value co \"example.org\")"},
		{"userType ne \"Employee\" and not (emails co \"example.com\" or emails.value co \"example.org\")"},
		{"emails[type eq \"work\" and value co \"@example.com\"] or ims[type eq \"xmpp\" and value co \"@foo.com\"]"},

		{"name pr and not (first eq \"test\") and another ne \"test\""},
		{"NAME PR AND NOT (FIRST EQ \"test\") AND ANOTHER NE \"test\"", "NAME pr and not (FIRST eq \"test\") and ANOTHER ne \"test\""},
		{"name pr or userName pr or title pr"},
	}
	for _, example := range examples {
		t.Run(example[0], func(t *testing.T) {
			fmt.Println(fmt.Sprintf("Input:\t%s", example[0]))
			ast, err := filter.ParseFilter(example[0])
			assert.NoError(t, err, "Example not parsed: "+example[0])
			out := ast.String()
			fmt.Println(fmt.Sprintf("Parsed:\t%s", out))
			match := example[1]
			if match == "" {
				match = example[0]
			}
			assert.Equal(t, match, out, "Check expected result matches: %s", match)
		})
	}
}
