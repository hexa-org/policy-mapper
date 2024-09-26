package cedar

import (
    "encoding/json"
    "fmt"
    "reflect"
    "testing"

    "github.com/cedar-policy/cedar-go"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
    "github.com/stretchr/testify/assert"
)

func TestMapCedarToHexa(t *testing.T) {
    tests := []struct {
        name  string
        cedar string
        idql  string
        err   bool
    }{
        {
            name: "Annotation",
            cedar: `
@comment("this is an annotation")
@description("Makes everything permitted")
permit (
    principal,
    action,
    resource
);`,
            idql: `{
 "meta": {
  "version": "0.7",
  "sourceData": {
   "annotations": {
    "comment": "this is an annotation",
    "description": "Makes everything permitted"
   }
  }
 },
 "subjects": [
  "any"
 ],
 "actions": [ ],
 "object": ""
}`,
            err: false,
        },
        {
            name: "AlicePhoto",
            cedar: `permit (
    principal == User::"alice",
    action == Action::"viewPhoto",
    resource == Photo::"VacationPhoto.jpg"
);`,
            idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "User:alice"
  ],
 "actions": [ "Action::viewPhoto" ],
 "object": "Photo::VacationPhoto.jpg"
}`,
            err: false},
        {
            name: "Multi-Action",
            cedar: `permit (
    principal is User in Group::"AVTeam",
    action in [PhotoOp::"view", PhotoOp::"edit", PhotoOp::"delete"],
    resource == Photo::"VacationPhoto.jpg"
);`,
            idql: `{
 "meta": {"version": "0.7"},
 "subjects": [
   "Type:User[Group::AVTeam]"
  ],
 "actions": [
    "PhotoOp::view",
    "PhotoOp::edit",
    "PhotoOp::delete"
 ],
 "object": "Photo::VacationPhoto.jpg"
}`, err: false},
        {
            name: "Conditions",
            cedar: `permit (
    principal in UserGroup::"AVTeam",
    action == Action::"viewPhoto",
    resource is Photo
)
when { resource in PhotoApp::Account::"stacey" }
unless { principal has parents };`,
            idql: `{
 "meta": {"version": "0.7"},
 "subjects": [
   "[UserGroup::AVTeam]"
  ],
 "actions": [ "Action::viewPhoto" ],
 "object": "Type:Photo",
 "Condition": {
  "Rule": "resource in PhotoApp::Account::\"stacey\" and not (principal.parents pr)",
  "Action": "allow"
 }
}`,
            err: false},
        {
            name: "action equals",
            cedar: `permit (
    principal is User,
    action == Action::"viewPhoto",
    resource
)
when { resource in PhotoShop::"Photo" };`,
            idql: `{
 "meta": {"version": "0.7"},
 "subjects": [
   "Type:User"
  ],
 "actions": [ "Action::viewPhoto" ],
 "object": "",
 "Condition": {
  "Rule": "resource in PhotoShop::\"Photo\"",
  "Action": "allow"
 }
}`,
            err: false},
    }
    mapper := NewCedarMapper(map[string]string{})
    for _, tt := range tests {
        tt := tt
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()
            fmt.Println("Testing:\n" + tt.name)
            result, err := mapper.MapCedarPolicyBytes("test", []byte(tt.cedar))
            testutilEquals(t, tt.err, err != nil)
            idqlOut := result.Policies[0].String()
            fmt.Println("Got:\n", idqlOut)
            fmt.Println("Want:\n", tt.idql)
            var want hexapolicy.PolicyInfo
            err = json.Unmarshal([]byte(tt.idql), &want)
            assert.NoError(t, err)
            assert.True(t, want.Equals(result.Policies[0]), "Policies should match")
            // testutilEquals(t, result.Policies[0], want)

            if tt.name == "Annotation" {
                assert.Len(t, result.Policies[0].Meta.SourceData["annotations"], 2, "Should be 2 annotations")
            }

        })
    }
}

func TestHexaToCedar(t *testing.T) {
    tests := []struct {
        name  string
        cedar string
        idql  string
        err   bool
    }{
        {
            name: "Annotation",
            cedar: `@comment("this is an annotation")
@description("Makes everything permitted")
permit (
  principal,
  action,
  resource
);`,
            idql: `{
 "meta": {
  "version": "0.7",
  "sourceData": {
   "annotations": {
    "comment": "this is an annotation",
    "description": "Makes everything permitted"
   }
  }
 },
 "subjects": [
  "any"
 ],
 "actions": [ ],
 "object": ""
}`,
            err: false,
        },
        {
            name: "AlicePhoto",
            cedar: `permit (
  principal == User::"alice",
  action == Action::"viewPhoto",
  resource == Photo::"VacationPhoto.jpg"
);`,
            idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "User:alice"
  ],
 "actions": [ "Action::viewPhoto" ],
 "object": "Photo::VacationPhoto.jpg"
}`,
            err: false},
        {
            name: "Multi-Subject",
            cedar: `permit (
  principal == User::"alice",
  action == Action::"viewPhoto",
  resource == Photo::"VacationPhoto.jpg"
);
permit (
  principal == User::"bob",
  action == Action::"viewPhoto",
  resource == Photo::"VacationPhoto.jpg"
);`,
            idql: `{
 "meta": {
   "version": "0.7"
  },
 "subjects": [
   "User:alice","User:bob"
  ],
 "actions": [ "Action::viewPhoto" ],
 "object": "Photo::VacationPhoto.jpg"
}`,
            err: false},
        {
            name: "Multi-Action",
            cedar: `permit (
  principal is User in Group::"AVTeam",
  action in [PhotoOp::"view", PhotoOp::"edit", PhotoOp::"delete"],
  resource == Photo::"VacationPhoto.jpg"
);`,
            idql: `{
 "meta": {"version": "0.7"},
 "subjects": [
   "Type:User[Group::AVTeam]"
  ],
 "actions": [
    "PhotoOp::view",
    "PhotoOp::edit",
    "PhotoOp::delete"
 ],
 "object": "Photo::VacationPhoto.jpg"
}`, err: false},
        {
            name: "Conditions",
            cedar: `permit (
  principal in UserGroup::"AVTeam",
  action == Action::"viewPhoto",
  resource is Photo
)
when { resource in PhotoApp::Account::"stacey" }
unless { principal has parents };`,
            idql: `{
 "meta": {"version": "0.7"},
 "subjects": [
   "[UserGroup::AVTeam]"
  ],
 "actions": [ "Action::viewPhoto" ],
 "object": "Type:Photo",
 "Condition": {
  "Rule": "resource in PhotoApp::Account::\"stacey\" and not (principal.parents pr)",
  "Action": "allow"
 }
}`,
            err: false},
        {
            name: "action equals",
            cedar: `permit (
  principal is User,
  action == Action::"viewPhoto",
  resource
)
when { resource in PhotoShop::"Photo" };`,
            idql: `{
 "meta": {"version": "0.7"},
 "subjects": [
   "Type:User"
  ],
 "actions": [ "Action::viewPhoto" ],
 "object": "",
 "Condition": {
  "Rule": "resource in PhotoShop::\"Photo\"",
  "Action": "allow"
 }
}`,
            err: false},
    }
    mapper := NewCedarMapper(map[string]string{})
    for _, tt := range tests {
        tt := tt
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()
            fmt.Println("Testing:\n" + tt.name)
            result, err := mapper.MapHexaPolicyBytes("test", []byte(tt.idql))
            testutilEquals(t, tt.err, err != nil)

            fmt.Println("Got:")
            fmt.Println(result)

            var cl1, cl2 cedar.PolicyList
            if err = cl1.UnmarshalCedar([]byte(result)); err != nil {
                assert.Fail(t, "Failed to parse result: "+err.Error())
            }

            fmt.Println("Want:")
            fmt.Println(tt.cedar)
            if err = cl2.UnmarshalCedar([]byte(tt.cedar)); err != nil {
                assert.Fail(t, err.Error())
            }
            allMatched := true
            for _, cp1 := range cl1 {
                itemMatch := false
                for _, cp2 := range cl2 {
                    if reflect.DeepEqual(cp1.AST(), cp2.AST()) {
                        itemMatch = true
                        break
                    }
                }
                if !itemMatch {
                    allMatched = false
                    break
                }
            }
            cl1 = nil // nil structures out to prevent anomalous errors
            cl2 = nil
            // Compare the object to eliminate spacing difference issues
            assert.True(t, allMatched, "got/want should match")

        })
    }
}

func testutilEquals[T any](t testing.TB, a, b T) {
    t.Helper()
    if reflect.DeepEqual(a, b) {
        return
    }
    t.Fatalf("\ngot  %+v\nwant %+v", a, b)
}
