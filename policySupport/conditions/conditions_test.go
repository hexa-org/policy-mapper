package conditions

import (
	"fmt"
	"testing"
)

func TestParseFilter(t *testing.T) {
	for _, example := range []string{
		"userName eq \"bjensen\"",
		"userName Eq \"bjensen\"",
		"name.familyName co \"O'Malley\"",
		"userName sw \"J\"",
		"urn:ietf:params:scim:schemas:core:2.0:User:userName sw \"J\"",
		"title pr",
		"meta.lastModified gt \"2011-05-13T04:42:34Z\"",
		"meta.lastModified ge \"2011-05-13T04:42:34Z\"",
		"meta.lastModified lt \"2011-05-13T04:42:34Z\"",
		"meta.lastModified le \"2011-05-13T04:42:34Z\"",
		"title pr and userType eq \"Employee\"",
		"title pr or userType eq \"Intern\"",
		"schemas eq \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\"",
		"userType eq \"Employee\" and (emails co \"example.com\" or emails.value co \"example.org\")",
		"userType ne \"Employee\" and not (emails co \"example.com\" or emails.value co \"example.org\")",
		"userType eq \"Employee\" and (emails.type eq \"work\")",
		"userType eq \"Employee\" and emails[type eq \"work\" and value co \"@example.com\"]",
		"emails[type eq \"work\" and value co \"@example.com\"] or ims[type eq \"xmpp\" and value co \"@foo.com\"]",

		"name pr and userName pr and title pr",
		"name pr and not (first eq \"test\") and another ne \"test\"",
		"NAME PR AND NOT (FIRST EQ \"test\") AND ANOTHER NE \"test\"",
		"name pr or userName pr or title pr",
	} {
		t.Run(example, func(t *testing.T) {
			cond := ConditionInfo{Rule: example}
			ast, err := ParseConditionRuleAst(cond)
			fmt.Println(ast)
			if err != nil {
				t.Error(err)
			}
		})
	}
}
