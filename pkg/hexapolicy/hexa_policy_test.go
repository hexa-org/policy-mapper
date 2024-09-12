package hexapolicy

import (
    "encoding/json"
    "fmt"
    "reflect"
    "testing"

    "github.com/stretchr/testify/assert"
)

var testPolicy1 = `
{
      "meta": {
        "version": "0.7"
      },
      "actions": [
         "http:GET:/accounting",
         "http:POST:/accounting"
      ],
      "subjects": [
          "user:accounting@hexaindustries.io"
      ],
      "condition": {
        "rule": "req.ip sw 127 and req.method eq POST",
        "action": "allow"
      },
      "object": "aResourceId",
      "scope": {
        "filter": "idql:username eq smith",
        "attributes": ["username","emails"]
      }
    }`

var testPolicy2 = `
{
      "meta": {
        "version": "0.7"
      },
      "actions": [
        "http:GET:/humanresources"
      ],
      "subjects": [
          "user:humanresources@hexaindustries.io"
      ],
      "object": "aResourceId"
    }`

var oldPolicy1 = `{
  "Meta": {
    "Version": "0.6"
  },
  "Actions": [
    {
      "ActionUri": "cedar:Action::view"
    }
  ],
  "Subject": {
    "Members": [
      "User:\"alice\""
    ]
  },
 "condition": {
        "rule": "req.ip sw 127 and req.method eq POST",
        "action": "allow"
      },
  "Object": {
    "resource_id": "cedar:Photo::\"VacationPhoto94.jpg\""
  },
"scope": {
        "filter": "idql:username eq smith",
        "attributes": ["username","emails"]
      }
}`

func getPolicies(t *testing.T) Policies {
    t.Helper()
    var policy1, policy2 PolicyInfo
    err := json.Unmarshal([]byte(testPolicy1), &policy1)
    assert.NoError(t, err)
    err = json.Unmarshal([]byte(testPolicy2), &policy2)
    assert.NoError(t, err)
    pols := &Policies{Policies: []PolicyInfo{policy1, policy2}}
    pols.CalculateEtags()
    return *pols
}

func TestReadPolicy(t *testing.T) {
    var policy1, policy2, policy3 PolicyInfo
    err := json.Unmarshal([]byte(testPolicy1), &policy1)
    assert.NoError(t, err, "Check no policy parse error #1")
    assert.NotNil(t, policy1.Subjects, "Subjects should not be nil")
    assert.Equal(t, 1, len(policy1.Subjects), "Should be one subject")
    err = json.Unmarshal([]byte(testPolicy2), &policy2)
    assert.NoError(t, err, "Check no policy parse error #2")

    _ = json.Unmarshal([]byte(testPolicy1), &policy3)

    etag := policy1.CalculateEtag()
    assert.NoError(t, err, "Check no error with etag gen")
    assert.NotNil(t, etag, "Check that an etag was returned")
    assert.False(t, policy1.Equals(policy2), "Check policies not equal")
    assert.True(t, policy1.Equals(policy3), "Check that policy1 and policy3 are equal")

}

func TestReadOldPolicy(t *testing.T) {
    var pol PolicyInfo
    err := json.Unmarshal([]byte(oldPolicy1), &pol)
    assert.NoError(t, err, "Check no policy parse error on old policy")
    assert.Equal(t, IdqlVersion, pol.Meta.Version, "policy should have current version")
    assert.NotNil(t, pol.Subjects, "Subjects should not be nil")
    assert.Len(t, pol.Subjects, 1, "should be one subject")
    assert.Len(t, pol.Actions, 1, "should be one action")
    assert.Equal(t, "cedar:Photo::\"VacationPhoto94.jpg\"", pol.Object.String(), "resource id should be converted")
}

func TestSubjectInfo_equals(t *testing.T) {
    policies := getPolicies(t)
    p1 := policies.Policies[0]
    p2 := policies.Policies[1]
    assert.NotNil(t, p1.Subjects, "Subjects should not be nil")
    assert.False(t, p1.Subjects.Equals(p2.Subjects))
    p3 := p1
    // check case sensitivity
    p3.Subjects = []string{"user:Accounting@Hexaindustries.io"}
    assert.True(t, p1.Subjects.Equals(p3.Subjects))
}

func TestPolicyInfo_actionEquals(t *testing.T) {
    policies := getPolicies(t)
    p1 := policies.Policies[0]
    p2 := policies.Policies[1]

    assert.False(t, p1.ActionsEqual(p2.Actions))

    p3 := p2

    // check that equivalence works with the same elements in the same order

    p3.Actions = p1.Actions
    assert.True(t, p1.ActionsEqual(p3.Actions))

    // Check that equivalence works out of order
    p3.Actions = []ActionInfo{"http:POST:/accounting", "http:GET:/accounting"}

    assert.True(t, p1.ActionsEqual(p3.Actions))

    p3.Actions = []ActionInfo{"http:POST:/accounting"}

    assert.False(t, p1.ActionsEqual(p3.Actions))
}

func TestObjectInfo_equals(t *testing.T) {
    policies := getPolicies(t)
    p1 := policies.Policies[0]
    p2 := policies.Policies[1]
    assert.True(t, p1.Object.equals(&p2.Object))
    p3 := p1
    p3.Object = "abc"
    assert.False(t, p1.Object.equals(&p3.Object))
}

func TestConditionInfo_Equals(t *testing.T) {
    policies := getPolicies(t)
    p1 := policies.Policies[0]
    p2 := policies.Policies[1]
    assert.False(t, p1.Condition.Equals(p2.Condition))

    p3 := p1

    assert.True(t, p1.Condition.Equals(p3.Condition))
}

func TestScope_equals(t *testing.T) {
    policies := getPolicies(t)

    scope1 := policies.Policies[0].Scope
    /*
       "scope": {
              "filter": "idql:username eq smith",
              "attributes": ["username","emails"]
            }
    */
    filter := "idql:username eq smith"
    scope2 := ScopeInfo{
        Filter:     &filter,
        Attributes: []string{"username", "emails"},
    }

    assert.Equal(t, ScopeTypeIDQL, scope1.Type())
    assert.Equal(t, "username eq smith", scope2.Value())

    assert.True(t, scope1.Equals(&scope2))

    filter = filter + "and surname eq smith"
    assert.False(t, scope1.Equals(&scope2))

    filter = "idql:username eq smith"

    scope2.Attributes = []string{"username"}
    assert.False(t, scope1.Equals(&scope2))

    scope2.Attributes = []string{"emails", "username"}
    assert.True(t, scope1.Equals(&scope2))

    scope2.Attributes = []string{"emails", "xyz"}
    assert.False(t, scope1.Equals(&scope2))

    filter = "dummy"
    scope2.Filter = &filter
    assert.Equal(t, ScopeTypeUnassigned, scope2.Type())
    assert.Equal(t, "dummy", scope2.Value())

    scope2.Filter = nil
    assert.Equal(t, ScopeTypeUnassigned, scope2.Type())

    assert.False(t, scope1.Equals(&scope2), "Test one filter is null")
    assert.False(t, scope2.Equals(scope1), "Test one filter is null")

    filter = "sQl:where username is \"sam\""
    scope2.Filter = &filter

    assert.Equal(t, "where username is \"sam\"", scope2.Value())
    assert.Equal(t, ScopeTypeSQL, scope2.Type())
    assert.False(t, scope1.Equals(&scope2), "Test filters of different types")

}

func TestPolicies_AddPolicies(t *testing.T) {
    var policies Policies
    var policy1, policy2 PolicyInfo
    err := json.Unmarshal([]byte(testPolicy1), &policy1)
    assert.NoError(t, err, "Should be no parsing error")
    err = json.Unmarshal([]byte(testPolicy2), &policy2)
    assert.NoError(t, err, "Should be no parsing error")

    policies.AddPolicy(policy1)
    assert.Len(t, policies.Policies, 1, "Should be 1 policy")
    policies.AddPolicy(policy2)

    var policies2 Policies
    policies2.AddPolicies(policies)
    assert.Len(t, policies2.Policies, 2, "Should be 2 policies")
}

func TestPolicyInfo_CalculateEtag(t *testing.T) {
    policies := getPolicies(t)

    p1 := policies.Policies[0]
    etag := p1.CalculateEtag()

    assert.Equal(t, etag, p1.Meta.Etag)

    pnew := p1
    pnew.Object = "abc"
    etag2 := pnew.CalculateEtag()

    assert.NotEqual(t, etag, etag2, "Should be different etags")
}

func TestPolicyInfo_Equals(t *testing.T) {
    policies := getPolicies(t)

    p3 := policies.Policies[0]
    // This will be used to make sure subject is case insensitive
    p3.Subjects = []string{"User:Accounting@Hexaindustries.io"}

    type fields struct {
        testPolicy PolicyInfo
    }
    type args struct {
        hexaPolicy PolicyInfo
    }
    tests := []struct {
        name   string
        fields fields
        args   args
        want   bool
    }{
        {
            name:   "Same policy",
            fields: fields{testPolicy: policies.Policies[0]},
            args:   args{hexaPolicy: policies.Policies[0]},
            want:   true,
        },
        {
            name:   "Diff policy",
            fields: fields{testPolicy: policies.Policies[0]},
            args:   args{hexaPolicy: policies.Policies[1]},
            want:   false,
        },
        {
            name:   "Subjects case test",
            fields: fields{testPolicy: policies.Policies[0]},
            args:   args{hexaPolicy: p3},
            want:   true,
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            p := &tt.fields.testPolicy
            assert.Equalf(t, tt.want, p.Equals(tt.args.hexaPolicy), "Equals(%v)", tt.args.hexaPolicy)
        })
    }
}

func TestPolicyInfo_Compare(t *testing.T) {
    policies := getPolicies(t)

    p3 := policies.Policies[0]
    // This will be used to make sure subject is case insensitive
    p3.Subjects = []string{"User:Accounting@Hexaindustries.io"}

    type fields struct {
        hexaPolicy PolicyInfo
    }
    type args struct {
        hexaPolicy PolicyInfo
    }
    tests := []struct {
        name   string
        fields fields
        args   args
        want   []string
    }{
        {
            name:   "Matching policy",
            fields: fields{hexaPolicy: policies.Policies[0]},
            args:   args{hexaPolicy: policies.Policies[0]},
            want:   []string{CompareEqual},
        },
        {
            name:   "Diff policy",
            fields: fields{hexaPolicy: policies.Policies[0]},
            args:   args{hexaPolicy: policies.Policies[1]},
            want:   []string{CompareDifSubject, CompareDifAction, CompareDifCondition},
        },
        {
            name:   "Subjects case test",
            fields: fields{hexaPolicy: policies.Policies[0]},
            args:   args{hexaPolicy: p3},
            want:   []string{CompareEqual},
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            p := &tt.fields.hexaPolicy
            assert.Equalf(t, tt.want, p.Compare(tt.args.hexaPolicy), "Compare(%v)", tt.args.hexaPolicy)
        })
    }
}

func TestPolicyDif_Report(t *testing.T) {
    pid := "abc"
    /*
           policyString := `{
         "meta": {
           "etag": "20-bf24e8e84dfa3c07c776a4e2ac31d1ca642502a9",
           "policyId": "abc"
         },
         "subjects": [
           "user1"
         ],
         "actions": [
           {
             "actionUri": "actionUri"
           }
         ],
         "object": {
           "resource_id": "aresource"
         }
       }`

    */

    testPolicy := PolicyInfo{
        Meta:      MetaInfo{PolicyId: &pid},
        Subjects:  []string{"user1"},
        Actions:   []ActionInfo{"actionUri"},
        Object:    "aresource",
        Condition: nil,
    }
    testPolicy.CalculateEtag()

    policyString := "\n" + testPolicy.String()

    type fields struct {
        Type          string
        PolicyId      string
        Hash          string
        DifTypes      []string
        PolicyExist   []PolicyInfo
        PolicyCompare *PolicyInfo
    }
    tests := []struct {
        name   string
        fields fields
        want   string
    }{
        {
            name: "New with Id",
            fields: fields{
                Type:          ChangeTypeNew,
                PolicyId:      pid,
                DifTypes:      []string{"SHOULD BE IGNORED"},
                PolicyCompare: &testPolicy,
            },
            want: "DIF: NEW PolicyId: abc" + policyString,
        },
        {
            name: "New with hash",
            fields: fields{
                Type:          ChangeTypeNew,
                Hash:          testPolicy.Meta.Etag,
                DifTypes:      []string{"SHOULD BE IGNORED"},
                PolicyCompare: &testPolicy,
            },
            want: "DIF: NEW Hash: " + testPolicy.Meta.Etag + policyString,
        },
        {
            name: "Change Equal with Id",
            fields: fields{
                Type:          ChangeTypeEqual,
                PolicyId:      pid,
                DifTypes:      []string{"SHOULD BE IGNORED"},
                PolicyCompare: &testPolicy,
            },
            want: "DIF: MATCHED PolicyId: abc" + policyString,
        },
        {
            name: "Ignore",
            fields: fields{
                Type:          ChangeTypeIgnore,
                PolicyId:      pid,
                DifTypes:      []string{"SHOULD BE IGNORED"},
                PolicyCompare: &testPolicy,
            },
            want: "DIF: UNSUPPORTED PolicyId: abc" + policyString,
        },
        {
            name: "Update",
            fields: fields{
                Type:          ChangeTypeUpdate,
                PolicyId:      pid,
                DifTypes:      []string{CompareDifAction, CompareDifObject},
                PolicyCompare: &testPolicy,
            },
            want: "DIF: UPDATE PolicyId: abc [ACTION OBJECT]" + policyString,
        },
        {
            name: "Delete",
            fields: fields{
                Type:          ChangeTypeDelete,
                PolicyId:      pid,
                DifTypes:      []string{"IGNORE"},
                PolicyCompare: &testPolicy,
            },
            want: "DIF: DELETE PolicyId: abc",
        },
        {
            name: "Unexpected",
            fields: fields{
                Type:          "unexpected",
                PolicyId:      pid,
                DifTypes:      []string{"IGNORE"},
                PolicyCompare: &testPolicy,
            },
            want: "DIF: Unexpected type PolicyId: abc" + policyString,
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            d := &PolicyDif{
                Type:          tt.fields.Type,
                PolicyId:      tt.fields.PolicyId,
                Hash:          tt.fields.Hash,
                DifTypes:      tt.fields.DifTypes,
                PolicyExist:   tt.fields.PolicyExist,
                PolicyCompare: tt.fields.PolicyCompare,
            }
            fmt.Println(d.Report())

            assert.Equalf(t, tt.want, d.Report(), "Report()")
        })
    }
}

func TestPolicyInfo_String(t *testing.T) {
    pid := "abc"
    policyString := `{
 "meta": {
  "etag": "20-6c1676cb067f5abe504031daef66a110f501a0f3",
  "policyId": "abc"
 },
 "subjects": [
  "user1"
 ],
 "actions": [
  "actionUri"
 ],
 "object": "aresource"
}`
    testPolicy := PolicyInfo{
        Meta:      MetaInfo{PolicyId: &pid},
        Subjects:  []string{"user1"},
        Actions:   []ActionInfo{"actionUri"},
        Object:    "aresource",
        Condition: nil,
    }
    testPolicy.CalculateEtag()
    result := testPolicy.String()
    assert.Equal(t, policyString, result, "String check")
}

func TestReconcilePolicies(t *testing.T) {
    policies := getPolicies(t)

    matchingPolicies := getPolicies(t)

    assert.Equal(t, policies.Policies[0].Meta.Etag, matchingPolicies.Policies[0].Meta.Etag)
    assert.Equal(t, policies.Policies[1].Meta.Etag, matchingPolicies.Policies[1].Meta.Etag)

    policiesWithIds := getPolicies(t)
    policiesIdSame := getPolicies(t)

    policiesWithChangesIds := getPolicies(t)

    policiesWithChangesHash := getPolicies(t)

    pid := "abc"
    pid2 := "def"

    policiesWithIds.Policies[0].Meta.PolicyId = &pid
    policiesWithIds.Policies[0].CalculateEtag()
    policiesWithIds.Policies[1].Meta.PolicyId = &pid2
    policiesWithIds.Policies[1].CalculateEtag()

    policiesIdSame.Policies[0].Meta.PolicyId = &pid
    policiesIdSame.Policies[1].Meta.PolicyId = &pid2

    policiesWithChangesIds.Policies[0].Meta.PolicyId = &pid
    policiesWithChangesIds.Policies[1].Meta.PolicyId = &pid2
    assert.Nil(t, policies.Policies[0].Meta.PolicyId)

    policiesWithChangesIds.Policies[0].Object = "changed"
    policiesWithChangesIds.Policies[0].CalculateEtag()
    assert.NotEqual(t, policiesWithIds.Policies[0].Object, "changed")

    policiesWithChangesHash.Policies[0].Object = "anotherchange"
    policiesWithChangesHash.Policies[0].CalculateEtag()

    policiesEmpty := Policies{
        Policies: []PolicyInfo{},
        App:      nil,
    }

    npid := "zyx"
    newPolicy := PolicyInfo{
        Meta: MetaInfo{
            Version:  IdqlVersion,
            PolicyId: &npid,
        },
        Subjects: []string{"phil.hunt@independentid.com"},
        Actions:  []ActionInfo{"http:GET:/admin", "http:POST:/admin"},
        Object:   "hexaindustries",
    }
    newPolicy.CalculateEtag()

    newPolicies := Policies{}
    origPolicy := policiesWithIds.Policies[0]
    newPolicies.AddPolicy(origPolicy)
    newPolicies.AddPolicy(newPolicy)

    type args struct {
        existingPolicies Policies
        comparePolicies  []PolicyInfo
        diffsOnly        bool
    }
    tests := []struct {
        name string
        args args
        want []PolicyDif
    }{
        {
            name: "Reconcile by etag",
            args: args{
                existingPolicies: policies,
                comparePolicies:  matchingPolicies.Policies,
                diffsOnly:        true,
            },
            want: []PolicyDif{},
        },
        {
            name: "Reconcile with ids",
            args: args{
                existingPolicies: policiesWithIds,
                comparePolicies:  policiesIdSame.Policies,
                diffsOnly:        true,
            },
            want: []PolicyDif{},
        },
        {
            name: "Reconcile with ids returning matches",
            args: args{
                existingPolicies: policiesWithIds,
                comparePolicies:  policiesIdSame.Policies,
                diffsOnly:        false,
            },
            want: []PolicyDif{
                {
                    Type:          ChangeTypeEqual,
                    PolicyId:      pid,
                    DifTypes:      []string{CompareEqual},
                    PolicyExist:   []PolicyInfo{policiesWithIds.Policies[0]},
                    PolicyCompare: &policiesIdSame.Policies[0],
                },
                {
                    Type:          ChangeTypeEqual,
                    PolicyId:      pid2,
                    DifTypes:      []string{CompareEqual},
                    PolicyExist:   []PolicyInfo{policiesWithIds.Policies[1]},
                    PolicyCompare: &policiesIdSame.Policies[1],
                },
            },
        },
        {
            name: "Reconcile by hashes returning matches",
            args: args{
                existingPolicies: policies,
                comparePolicies:  matchingPolicies.Policies,
                diffsOnly:        false,
            },
            want: []PolicyDif{
                {
                    Type:          ChangeTypeEqual,
                    Hash:          policies.Policies[0].Meta.Etag,
                    DifTypes:      []string{CompareEqual},
                    PolicyExist:   []PolicyInfo{policies.Policies[0]},
                    PolicyCompare: &matchingPolicies.Policies[0],
                },
                {
                    Type:          ChangeTypeEqual,
                    Hash:          policies.Policies[1].Meta.Etag,
                    DifTypes:      []string{CompareEqual},
                    PolicyExist:   []PolicyInfo{policies.Policies[1]},
                    PolicyCompare: &matchingPolicies.Policies[1],
                },
            },
        },
        {
            name: "Changes with Ids",
            args: args{
                existingPolicies: policiesWithIds,
                comparePolicies:  policiesWithChangesIds.Policies,
                diffsOnly:        true,
            },
            want: []PolicyDif{{
                Type:          ChangeTypeUpdate,
                PolicyId:      pid,
                Hash:          "",
                DifTypes:      []string{CompareDifObject},
                PolicyExist:   []PolicyInfo{policiesWithIds.Policies[0]},
                PolicyCompare: &policiesWithChangesIds.Policies[0],
            }},
        },
        {
            name: "Changes with Hash Compare",
            args: args{
                existingPolicies: policies,
                comparePolicies:  policiesWithChangesHash.Policies,
                diffsOnly:        true,
            },
            want: []PolicyDif{
                {
                    Type:          ChangeTypeNew,
                    Hash:          policiesWithChangesHash.Policies[0].CalculateEtag(),
                    PolicyExist:   nil,
                    PolicyCompare: &policiesWithChangesHash.Policies[0],
                    DifTypes:      nil,
                },
                {
                    Type:        ChangeTypeDelete,
                    Hash:        policies.Policies[0].CalculateEtag(),
                    PolicyExist: []PolicyInfo{policies.Policies[0]},
                    DifTypes:    nil,
                },
            },
        },
        {
            name: "Empty Set Existing (causes new)",
            args: args{
                existingPolicies: policiesEmpty,
                comparePolicies:  policiesWithChangesHash.Policies,
                diffsOnly:        true,
            },
            want: []PolicyDif{
                {
                    Type:          ChangeTypeNew,
                    Hash:          policiesWithChangesHash.Policies[0].CalculateEtag(),
                    PolicyExist:   nil,
                    PolicyCompare: &policiesWithChangesHash.Policies[0],
                    DifTypes:      nil,
                },
                {
                    Type:          ChangeTypeNew,
                    Hash:          policiesWithChangesHash.Policies[1].CalculateEtag(),
                    PolicyExist:   nil,
                    PolicyCompare: &policiesWithChangesHash.Policies[1],
                    DifTypes:      nil,
                },
            },
        },
        {
            name: "Empty Set Compare with hash (causes delete)",
            args: args{
                existingPolicies: policies,
                comparePolicies:  policiesEmpty.Policies,
                diffsOnly:        true,
            },
            want: []PolicyDif{
                {
                    Type:          ChangeTypeDelete,
                    PolicyId:      "",
                    Hash:          policies.Policies[0].Meta.Etag,
                    PolicyExist:   []PolicyInfo{policies.Policies[0]},
                    PolicyCompare: nil,
                    DifTypes:      nil,
                },
                {
                    Type:          ChangeTypeDelete,
                    PolicyId:      "",
                    Hash:          policies.Policies[1].Meta.Etag,
                    PolicyExist:   []PolicyInfo{policies.Policies[1]},
                    PolicyCompare: nil,
                    DifTypes:      nil,
                },
            },
        },
        {
            name: "Empty Set Compare with id (causes delete)",
            args: args{
                existingPolicies: policiesWithIds,
                comparePolicies:  []PolicyInfo{},
                diffsOnly:        true,
            },
            want: []PolicyDif{
                {
                    Type:          ChangeTypeDelete,
                    PolicyId:      *policiesWithIds.Policies[0].Meta.PolicyId,
                    PolicyExist:   []PolicyInfo{policiesWithIds.Policies[0]},
                    PolicyCompare: nil,
                    DifTypes:      nil, // For some reason, if this is not set to nil, random test errors occur
                },
                {
                    Type:          ChangeTypeDelete,
                    PolicyId:      *policiesWithIds.Policies[1].Meta.PolicyId,
                    PolicyExist:   []PolicyInfo{policiesWithIds.Policies[1]},
                    PolicyCompare: nil,
                    DifTypes:      nil,
                },
            },
        },
        {
            name: "Add New Policy and Remove",
            args: args{
                existingPolicies: policiesWithIds,
                comparePolicies:  newPolicies.Policies,
                diffsOnly:        true,
            },
            want: []PolicyDif{
                {
                    Type:          ChangeTypeNew,
                    PolicyId:      npid,
                    Hash:          newPolicy.Meta.Etag,
                    PolicyExist:   nil,
                    PolicyCompare: &newPolicy,
                    DifTypes:      nil,
                },
                {
                    Type:          ChangeTypeDelete,
                    PolicyId:      *policiesWithIds.Policies[1].Meta.PolicyId,
                    PolicyExist:   []PolicyInfo{policiesWithIds.Policies[1]},
                    PolicyCompare: nil,
                    DifTypes:      nil,
                },
            },
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            assert.Equal(t, policies.Policies[0].Meta.Etag, matchingPolicies.Policies[0].Meta.Etag)
            assert.Equal(t, policies.Policies[1].Meta.Etag, matchingPolicies.Policies[1].Meta.Etag)

            got := tt.args.existingPolicies.ReconcilePolicies(tt.args.comparePolicies, tt.args.diffsOnly)

            assert.Equal(t, len(tt.want), len(got))

            matchFail := false
            for _, value := range got {
                match := false
                for _, want := range tt.want {
                    if reflect.DeepEqual(want, value) {
                        match = true
                        break
                    }
                }
                if !match {
                    matchFail = true
                }
            }
            assert.Falsef(t, matchFail, "ReconcilePolicies(%v, %v, %v)", tt.args.existingPolicies, tt.args.comparePolicies, tt.args.diffsOnly)
            // assert.Equalf(t, tt.want, got, "ReconcilePolicies(%v, %v, %v)", tt.args.existingPolicies, tt.args.comparePolicies, tt.args.diffsOnly)
        })
    }
}
