package conditions_test

import (
    "fmt"
    "testing"

    "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
    "github.com/stretchr/testify/assert"
)

func TestParseFilter(t *testing.T) {
    for _, example := range []string{
        "(level gt 5 or test eq \"abc\" or level lt 10) and (username sw \"emp\" or username eq \"guest\")",
        "(userName eq \"bjensen\")",
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
        "emails[type eq \"work\" and value ew \"strata.io\"]",
    } {
        t.Run(example, func(t *testing.T) {
            cond := conditions.ConditionInfo{Rule: example}
            ast, err := conditions.ParseConditionRuleAst(cond)
            assert.NoError(t, err, "Parse error against -->"+cond.Rule+"<--")
            astString := conditions.SerializeExpression(ast)
            assert.NoError(t, err, "Serialization error against -->"+cond.Rule+"<--")
            fmt.Println(astString)
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

    // Test Provider mapping
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

func TestWalker(t *testing.T) {
    cond := conditions.ConditionInfo{Rule: "level gt 6 and not(expired eq true)"}
    ast, err := conditions.ParseExpressionAst(cond.Rule)
    assert.NotNilf(t, ast, "ast is not nil")
    assert.NoError(t, err, "no error parsing expression")

    back := conditions.SerializeExpression(ast)
    assert.NotNilf(t, ast, "ast is not nil")
    assert.Equal(t, "level gt 6 and not(expired eq true)", back)

    ast, err = conditions.ParseExpressionAst("(level gt 6 or rank lt 5) and not username pr")
    assert.NotNilf(t, ast, "ast is not nil")
    back2 := conditions.SerializeExpression(ast)
    fmt.Println(back2)
}

func TestEquals(t *testing.T) {

    tests := []struct {
        Name     string
        R1       string
        R2       string
        Expected bool
    }{
        {
            "Same with Not",
            "level gt 6 and not(expired eq true)",
            "level gt 6 and not(expired eq true)",
            true,
        },
        {
            "Same with precedence",
            "level gt 6 and (expired eq true)",
            "level gt 6 and expired eq true",
            true,
        },
        {
            "Same but reverse",
            "level gt 6 and not(expired eq true)",
            " not(expired eq true) and level gt 6 ",
            true,
        },
        {
            "Not same",
            "level gt 6 and not(expired eq true)",
            "(expired eq true) and level gt 6",
            false,
        },
        {
            "Same different not",
            "level gt 6 and not(expired eq true)",
            "not(level gt 6) and expired eq true",
            false,
        },
        {
            "Lots of logical",
            "(level gt 5 or test eq \"abc\" or level lt 10) and (username sw \"emp\" or username eq \"guest\")",
            "(username eq \"guest\" or username sw \"emp\") and (level gt 5 or test eq \"abc\" or level lt 10)",
            true,
        },
        {
            "Switched operator ",
            "(level gt 5 or test eq \"abc\" or level lt 10) and (username sw \"emp\" or username eq \"guest\")",
            "(username sw \"emp\" or username eq \"guest\") or (level gt 5 or test eq \"abc\" or level lt 10)",
            false,
        },
    }

    for _, test := range tests {
        t.Run(test.Name, func(t *testing.T) {
            fmt.Println(fmt.Sprintf("R1:\t%s", test.R1))
            fmt.Println(fmt.Sprintf("R2:\t%s", test.R2))
            condition1 := conditions.ConditionInfo{Rule: test.R1}
            condition2 := conditions.ConditionInfo{Rule: test.R2}

            assert.Equal(t, test.Expected, condition1.Equals(&condition2), "Check expected result matches: %s", test.Expected)
        })
    }

}
