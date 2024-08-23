package cedar

import (
    "fmt"
    "reflect"
    "testing"
)

const policyCedar = `
@comment("this is an annotation")
@description("Makes everything permitted")
permit (
    principal,
    action,
    resource
);

permit (
    principal == User::"alice",
    action == Action::"viewPhoto",
    resource == Photo::"VacationPhoto.jpg"
);

permit (
    principal is User in UserGroup::"AVTeam",
    action in [PhotoOp::"view", PhotoOp::"edit", PhotoOp::"delete"],
    resource == Photo::"VacationPhoto.jpg"
);

permit (
    principal in UserGroup::"AVTeam",
    action == Action::"viewPhoto",
    resource is Photo
)
when { resource in PhotoApp::Account::"stacey" }
unless { principal has parents };

permit (
    principal is User,
    action == Action::"viewPhoto",
    resource
)
when { resource in PhotoShop::"Photo" };
`

const policyTemplate = `
permit(
    principal in ?principal,
    action in [hexa_avp::Action::"ReadAccount"],
    resource
);
`

const entitiesJSON = `[
  {
    "uid": { "type": "User", "id": "alice" },
    "attrs": { "age": 18 },
    "parents": []
  },
  {
    "uid": { "type": "Photo", "id": "VacationPhoto.jpg" },
    "attrs": {},
    "parents": [{ "type": "Album", "id": "jane_vacation" }]
  }
]`

func TestMapCedar(t *testing.T) {
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
  "sourceData": {
   "annotations": {
    "comment": "this is an annotation",
    "description": "Makes everything permitted"
   }
  }
 },
 "subject": {
  "members": [
   "any"
  ]
 },
 "actions": null,
 "object": {
  "resource_id": ""
 }
}`,
            err: false,
        },
        {"AlicePhoto", `permit (
    principal == User::"alice",
    action == Action::"viewPhoto",
    resource == Photo::"VacationPhoto.jpg"
);`, `{
 "meta": {},
 "subject": {
  "members": [
   "User:alice"
  ]
 },
 "actions": [
  {
   "actionUri": "viewPhoto"
  }
 ],
 "object": {
  "resource_id": "Photo::\"VacationPhoto.jpg\""
 }
}`, false},
        {"Multi-Action", `permit (
    principal is User in Group::"AVTeam",
    action in [PhotoOp::"view", PhotoOp::"edit", PhotoOp::"delete"],
    resource == Photo::"VacationPhoto.jpg"
);`, `{
 "meta": {},
 "subject": {
  "members": [
   "Group:\"AVTeam\".(User)"
  ]
 },
 "actions": [
  {
   "actionUri": "PhotoOp::\"view\""
  },
  {
   "actionUri": "PhotoOp::\"edit\""
  },
  {
   "actionUri": "PhotoOp::\"delete\""
  }
 ],
 "object": {
  "resource_id": "Photo::\"VacationPhoto.jpg\""
 }
}`, false},
        {"Conditions", `permit (
    principal in UserGroup::"AVTeam",
    action == Action::"viewPhoto",
    resource is Photo
)
when { resource in PhotoApp::Account::"stacey" }
unless { principal has parents };`,
            `{
 "meta": {},
 "subject": {
  "members": [
   "Group:UserGroup::\"AVTeam\""
  ]
 },
 "actions": [
  {
   "actionUri": "viewPhoto"
  }
 ],
 "object": {
  "resource_id": "Type:Photo"
 },
 "Condition": {
  "Rule": "resource in PhotoApp::Account::\"stacey\" and not (principal.parents pr)",
  "Action": "allow"
 }
}`, false},
        {"action equals", `permit (
    principal is User,
    action == Action::"viewPhoto",
    resource
)
when { resource in PhotoShop::"Photo" };`, `{
 "meta": {},
 "subject": {
  "members": [
   "Type:User"
  ]
 },
 "actions": [
  {
   "actionUri": "viewPhoto"
  }
 ],
 "object": {
  "resource_id": ""
 },
 "Condition": {
  "Rule": "resource in PhotoShop::\"Photo\"",
  "Action": "allow"
 }
}`, false},
    }

    for _, tt := range tests {
        tt := tt
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()
            fmt.Println("Testing:\n" + tt.cedar)
            result, err := MapCedarPolicyBytes("test", []byte(tt.cedar))
            testutilEquals(t, tt.err, err != nil)
            idqlOut := result.Policies[0].String()
            fmt.Println("Mapped:\n" + idqlOut)
            testutilEquals(t, idqlOut, tt.idql)

        })
    }

}

func TestMapTemplate(t *testing.T) {
    /*  Looks like this has to be done using Go AVP library
        result, err := MapCedarPolicyBytes("test", []byte(policyTemplate))
        assert.NoError(t, err)
        assert.Len(t, result.Policies, 1)

    */
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
