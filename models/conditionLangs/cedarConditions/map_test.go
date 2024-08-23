package cedarConditions

import (
    "fmt"
    "reflect"
    "strings"
    "testing"

    "github.com/cedar-policy/cedar-go/x/exp/parser"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
)

func TestMapCedar(t *testing.T) {
    tests := []struct {
        name string
        in   string
        out  *conditions.ConditionInfo
        err  bool
    }{
        {"Empty test", "", nil, false},
        {"When equal", "when { resource.owner == principal }", &conditions.ConditionInfo{
            Rule:   "resource.owner eq principal",
            Action: conditions.AAllow,
        }, false},
        {"Precedence ands", "when { ( resource.owner == principal.id ) && resource.id == \"1234\" && principal.type == \"customer\" }", &conditions.ConditionInfo{
            Rule:   "(resource.owner eq principal.id) and resource.id eq \"1234\" and principal.type eq \"customer\"",
            Action: conditions.AAllow,
        }, false},
        {"Precedence ors", "when { ( resource.owner == principal.id ) || resource.id == \"1234\" && principal.type == \"customer\" }", &conditions.ConditionInfo{
            Rule:   "(resource.owner eq principal.id) or resource.id eq \"1234\" and principal.type eq \"customer\"",
            Action: conditions.AAllow,
        }, false},
        {"Nested", "when { resource.owner == principal.id  && (principal.type == \"staff\" || principal.type == \"employee\") || resource.id == \"1234\" && principal.type == \"customer\" }", &conditions.ConditionInfo{
            Rule:   "resource.owner eq principal.id and (principal.type eq \"staff\" or principal.type eq \"employee\") or resource.id eq \"1234\" and principal.type eq \"customer\"",
            Action: conditions.AAllow,
        }, false},
        {"Unless equal", "unless { resource.owner == principal }", &conditions.ConditionInfo{
            Rule:   "resource.owner eq principal",
            Action: conditions.ADeny,
        }, false},
        {"Unless compound", "unless { resource.owner == principal.id  && (principal.type == \"staff\" || principal.type == \"employee\") || resource.id == \"1234\" && principal.type == \"customer\" }", &conditions.ConditionInfo{
            Rule:   "resource.owner eq principal.id and (principal.type eq \"staff\" or principal.type eq \"employee\") or resource.id eq \"1234\" and principal.type eq \"customer\"",
            Action: conditions.ADeny,
        }, false},
        {"Is test", "when { resource is Photo }", &conditions.ConditionInfo{
            Rule:   "resource is Photo",
            Action: conditions.AAllow,
        }, false},
        {"In test", "when { resource in Album::\"alice_vacation\" }", &conditions.ConditionInfo{
            Rule:   "resource in Album::\"alice_vacation\"",
            Action: conditions.AAllow,
        }, false},
        {"In set", "when { resource.id in [\"a\",\"b\"] }", &conditions.ConditionInfo{
            Rule:   "resource.id in [\"a\", \"b\"]",
            Action: conditions.AAllow,
        }, false},
        {"Has Ident", "when { resource has ident }", &conditions.ConditionInfo{
            Rule:   "resource.ident pr",
            Action: conditions.AAllow,
        }, false},
        {"Has Literal Ident", "when { resource has \"literal ident\" }", &conditions.ConditionInfo{
            Rule:   "resource.\"literal ident\" pr",
            Action: conditions.AAllow,
        }, false},

        {"Is In", "when { principal is User in Group::\"accounting\"}", &conditions.ConditionInfo{
            Rule:   "principal is User and principal in Group::\"accounting\"",
            Action: conditions.AAllow,
        }, false},
        {"Multi-or", "when { principal.id > 4 || principal.type >= \"c\" || resource.id < 100 || resource.name <= \"m\" }",
            &conditions.ConditionInfo{
                Rule:   "principal.id gt 4 or principal.type ge \"c\" or resource.id lt 100 or resource.name le \"m\"",
                Action: conditions.AAllow,
            }, false},
        {"Multi Clause", `
when { resource is Photo }
when { resource has ident }
unless { resource.owner == principal.id }
`, &conditions.ConditionInfo{
            Rule:   "resource is Photo and resource.ident pr and not (resource.owner eq principal.id)",
            Action: conditions.AAllow,
        }, false},
        {"Operand test", `
when { principal.id > 4 && principal.type >= "c" && resource.id < 100 && resource.name <= "m"}
when { resource.docid > 1000 || resource.docid <= 100 }
when { resource.owner != "somebody" }
`, &conditions.ConditionInfo{
            Rule:   "principal.id gt 4 and principal.type ge \"c\" and resource.id lt 100 and resource.name le \"m\" and (resource.docid gt 1000 or resource.docid le 100) and resource.owner ne \"somebody\"",
            Action: conditions.AAllow,
        }, false},
        {"Contains", "when { principal.name.contains(\"smith\") }",
            &conditions.ConditionInfo{
                Rule:   "principal.name co \"smith\"",
                Action: conditions.AAllow,
            }, false},
        {"Record set addressing", "when { principal[\"name\"] == \"smith\" }",
            &conditions.ConditionInfo{
                Rule:   "principal.name eq \"smith\"",
                Action: conditions.AAllow,
            }, false},
        {"Record multi-set addressing", "when { principal[\"name\"][\"last\"] == \"smith\" }",
            &conditions.ConditionInfo{
                Rule:   "principal.name.last eq \"smith\"",
                Action: conditions.AAllow,
            }, false},
        {"Record mix-set addressing", "when { principal[\"name\"].last == \"smith\" }",
            &conditions.ConditionInfo{
                Rule:   "principal.name.last eq \"smith\"",
                Action: conditions.AAllow,
            }, false},
        {"Entity addressing", "when { principal == User::\"a1b2c3d4-e5f6-a1b2-c3d4-EXAMPLE11111\" }",
            &conditions.ConditionInfo{
                Rule:   "principal eq User::\"a1b2c3d4-e5f6-a1b2-c3d4-EXAMPLE11111\"",
                Action: conditions.AAllow,
            }, false},
        {"Dot operand test", "when { principal.id.greaterThan(4) || principal.id.greaterThanOrEqual(100) || principal.access.lessThan(4) || principal.name.lessThanOrEqual(\"m\") }",
            &conditions.ConditionInfo{
                Rule:   "principal.id gt 4 or principal.id ge 100 or principal.access lt 4 or principal.name le \"m\"",
                Action: conditions.AAllow,
            }, false},

        // negative tests
        {"primary-if-test-error", "when {\n (if principal has name then principal.name else \"Joe\") == \"Alice\"\n}",
            &conditions.ConditionInfo{}, true},
        {"expression-if-error", "when { principal.id > 4 && (if principal.id == \"1\" then true else false) }",
            &conditions.ConditionInfo{}, true},
        {"recinit-error", "when { {\"key\": \"some value\", id: \"another value\"} }", &conditions.ConditionInfo{}, true},
        {"ContainsAll-error", "when { principal.name.containsAll([\"a\",\"b\"]) }",
            &conditions.ConditionInfo{
                Rule:   "principal.name co \"smith\"",
                Action: conditions.AAllow,
            }, true},
    }

    for _, tt := range tests {
        tt := tt
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()

            sb := strings.Builder{}
            sb.WriteString("permit ( principal, action, resource )\n")
            sb.WriteString(tt.in)
            sb.WriteString(";")
            policyInput := sb.String()

            tokens, err := parser.Tokenize([]byte(policyInput))
            testutilOK(t, err)
            policies, err := parser.Parse(tokens)
            testutilOK(t, err)
            hexaCond, err := doMapCedar(policies)
            testutilEquals(t, err != nil, tt.err)
            if err == nil {
                testutilEquals(t, hexaCond, tt.out)
            }

        })
    }
}

var mapper = CedarConditionMapper{NameMapper: conditions.NewNameMapper(map[string]string{})}

func doMapHexa(hexaCondition string) (string, error) {
    cond := &conditions.ConditionInfo{
        Rule:   hexaCondition,
        Action: conditions.AAllow,
    }

    return mapper.MapConditionToCedar(cond)
}
func doMapCedar(policies parser.Policies) (*conditions.ConditionInfo, error) {
    if len(policies) == 0 {
        return nil, nil
    }

    conditions := policies[0].Conditions
    if conditions == nil {
        return nil, nil
    }
    hexaCond, err := MapCedarConditionToHexa(conditions)
    if err != nil {
        return nil, err
    }
    return hexaCond, err
}

func TestMapHexa(t *testing.T) {
    examples := [][3]string{
        {"ManyOrs", "((userName eq A) or (username eq \"B\")) or username eq C", "when { (userName == \"A\" || username == \"B\") || username == \"C\" }"},
        {"Pr test", "principal.title pr", "when { principal has title }"},
        {"MultiAnd", "principal.name pr and principal.username pr and principal.title pr", "when { principal has name }\nwhen { principal has username }\nwhen { principal has title }"},
        {"Contains", "name.familyName co \"O'Malley\"", "when { name.familyName.contains(\"O'Malley\") }"},
        {"Precedence", "(username eq \"bjensen\")", "when { username == \"bjensen\" }"},
        {"Spacing", "userName   eq  \"bjensen\"", "when { userName == \"bjensen\" }"},
        {"GT Test", "level gt 12", "when { level > 12 }"},
        {"Numeric", "level gt 12.3", "when { level > 12.3 }"},
        {"Exponential", "level eq 123.45e-5", "when { level == 123.45e-5 }"},
        {"Embedded chars", "emails.type eq \"w o(rk)\"", "when { emails.type == \"w o(rk)\" }"},
        {"Operator case test", "userName Eq \"bjensen\"", "when { userName == \"bjensen\" }"},
        {"Deep Ors", "((userName eq A) or (username eq \"B\")) or username eq C", "when { (userName == \"A\" || username == \"B\") || username == \"C\" }"},
        {"Starts with", "userName sw \"J\"", "when { userName.startsWith(\"J\") }"},
        {"Long Urn", "urn:ietf:params:scim:schemas:core:2.0:User:userName sw \"J\"", "when { urn:ietf:params:scim:schemas:core:2.0:User:userName.startsWith(\"J\") }"},

        {"Nested precedence or", "userType eq \"Employee\" and (emails co \"example.com\" or emails.value co \"example.org\")", "when { userType == \"Employee\" }\nwhen { emails.contains(\"example.com\") || emails.value.contains(\"example.org\") }"},
        {"Nested Not or", "userType eq \"Employee\" and not(emails co \"example.com\" or emails.value co \"example.org\")", "when { userType == \"Employee\" }\nunless { emails.contains(\"example.com\") || emails.value.contains(\"example.org\") }"},
        // {"emails[type eq \"work\" and value co \"@example.com\"] or ims[type eq \"xmpp\" and value co \"@foo.com\"]"},
        {"NotExpression", "not(principal.name eq gerry)", "unless { principal.name == \"gerry\" }"},
        {"Or NotExpression", "principal.title pr or not(principal.name eq gerry)", "when { principal has title || !( principal.name == \"gerry\" ) }"},
        {"Or Not LogicalExpression", "principal.title pr or not(principal.name eq phil or principal.name eq gerry)", "when { principal has title || !( principal.name == \"phil\" || principal.name == \"gerry\" ) }"},
        {"And Not And", "principal.name pr and not (first eq \"test\") and another ne \"test\"", "when { principal has name }\nunless { first == \"test\" }\nwhen { another != \"test\" }"},
        {"ands with embedded or", "principal.name pr and first eq \"test\" and ( another ne \"test\" or def lt 123 or abc eq \"123\")", "when { principal has name }\nwhen { first == \"test\" }\nwhen { another != \"test\" || def < 123 || abc == 123 }"},

        {
            "Attribute Expressions",
            "principal.name LT \"z\" or usage le 4 or logincount ge 2 or ( principal.name ew \"smith\" and principal in Groups::\"accounting\" and (account.active eq true or account.enabled ne false ))",
            "when { principal.name < \"z\" || usage <= 4 || logincount >= 2 || (principal.name.endsWith(\"smith\") && principal in Groups::\"accounting\" && (account.active == true || account.enabled != false)) }",
        },
        // {"emails[type eq work and value ew \"h[exa].org\"]", "emails[type eq \"work\" and value ew \"h[exa].org\"]"},
    }

    for _, example := range examples {
        t.Run(example[0], func(t *testing.T) {

            fmt.Println(fmt.Sprintf("Input:\n%s", example[1]))

            result, err := doMapHexa(example[1])
            testutilOK(t, err)
            fmt.Println(fmt.Sprintf("Result:\n%s", result))
            testUtilCederConditionEquals(t, result, example[2])
        })
    }
}

func testUtilCederConditionEquals(t testing.TB, got string, want string) {
    t.Helper()
    if got != want {
        t.Fatalf("\ngot \t%+v\nwant\t%+v", got, want)
    }
}

func testutilEquals[T any](t testing.TB, a, b T) {
    t.Helper()
    if reflect.DeepEqual(a, b) {
        return
    }
    t.Fatalf("\ngot  %+v\nwant %+v", a, b)
}

func testutilOK(t testing.TB, err error) {
    t.Helper()
    if err == nil {
        return
    }
    t.Fatalf("got %v want nil", err)
}

func testutilError(t testing.TB, err error) {
    t.Helper()
    if err != nil {
        return
    }
    t.Fatalf("got nil want error")
}
