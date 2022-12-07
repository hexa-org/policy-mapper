package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"policy-conditions/policySupport/conditions"
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
			cond := conditions.ConditionInfo{Rule: example}
			ast, err := conditions.ParseConditionRuleAst(cond)
			fmt.Println(ast)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestNewNameMapper(t *testing.T) {
	mapper := conditions.NewNameMapper(map[string]string{
		"a":           "b",
		"c":           "d",
		"username":    "userid",
		"emails.type": "mail.type",
	})

	//Test Provider mapping
	assert.Equal(t, "b", mapper.GetProviderAttributeName("a"), "a produces b")
	assert.Equal(t, "userid", mapper.GetProviderAttributeName("userName"), "userName prodeuces userid")
	assert.Equal(t, "undefined", mapper.GetProviderAttributeName("undefined"), "undefined maps as undefined")
	assert.Equal(t, "mail.type", mapper.GetProviderAttributeName("emails.type"), "emails.type maps to mail.type")

	// Test ReversMapping
	path := mapper.GetHexaFilterAttributePath("mail.type")

	assert.Equal(t, "emails.type", path, "should be emails.type")

	path = mapper.GetHexaFilterAttributePath("unknown.type")
	assert.Equal(t, "unknown.type", path, "should be unknown.type")

	path = mapper.GetHexaFilterAttributePath("d")
	assert.Equal(t, "c", path, "attribute should be c")

}
