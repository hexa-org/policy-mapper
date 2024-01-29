package hexapolicy

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testPolicy1 = `
{
      "meta": {
        "version": "0.6"
      },
      "actions": [
        {
          "actionuri": "http:GET:/accounting"
        },
        {
          "actionuri": "http:POST:/accounting"
        }
      ],
      "subject": {
        "members": [
          "accounting@hexaindustries.io"
        ]
      },
      "condition": {
        "rule": "req.ip sw 127 and req.method eq POST",
        "action": "allow"
      },
      "object": {
        "resource_id": "aResourceId"
      }
    }`

var testPolicy2 = `
{
      "meta": {
        "version": "0.6"
      },
      "actions": [
        {
          "actionuri": "http:GET:/humanresources"
        }
      ],
      "subject": {
        "members": [
          "humanresources@hexaindustries.io"
        ]
      },
      "object": {
        "resource_id": "aResourceId"
      }
    }`

func getPolicies() Policies {
	var policy1, policy2 PolicyInfo
	_ = json.Unmarshal([]byte(testPolicy1), &policy1)
	_ = json.Unmarshal([]byte(testPolicy2), &policy2)
	pols := &Policies{Policies: []PolicyInfo{policy1, policy2}}
	pols.CalculateEtags()
	return *pols
}

func TestReadPolicy(t *testing.T) {
	var policy1, policy2, policy3 PolicyInfo
	err := json.Unmarshal([]byte(testPolicy1), &policy1)
	assert.NoError(t, err, "Check no policy parse error #1")

	err = json.Unmarshal([]byte(testPolicy2), &policy2)
	assert.NoError(t, err, "Check no policy parse error #2")

	_ = json.Unmarshal([]byte(testPolicy1), &policy3)

	etag := policy1.CalculateEtag()
	assert.NoError(t, err, "Check no error with etag gen")
	assert.NotNil(t, etag, "Check that an etag was returned")
	assert.False(t, policy1.Equals(policy2), "Check policies not equal")
	assert.True(t, policy1.Equals(policy3), "Check that policy1 and policy3 are equal")

}

func TestSubjectInfo_equals(t *testing.T) {
	policies := getPolicies()
	p1 := policies.Policies[0]
	p2 := policies.Policies[1]
	assert.False(t, p1.Subject.equals(&p2.Subject))
	p3 := p1
	// check case sensitivity
	p3.Subject = SubjectInfo{Members: []string{"Accounting@Hexaindustries.io"}}
	assert.True(t, p1.Subject.equals(&p3.Subject))
}

func TestPolicyInfo_actionEquals(t *testing.T) {
	policies := getPolicies()
	p1 := policies.Policies[0]
	p2 := policies.Policies[1]

	assert.False(t, p1.actionEquals(p2.Actions))

	p3 := p2

	// check that equivalence works with the same elements in the same order

	p3.Actions = p1.Actions
	assert.True(t, p1.actionEquals(p3.Actions))

	// Check that equivalence works out of order
	p3.Actions = []ActionInfo{{ActionUri: "http:POST:/accounting"}, {ActionUri: "http:GET:/accounting"}}

	assert.True(t, p1.actionEquals(p3.Actions))

	p3.Actions = []ActionInfo{{ActionUri: "http:POST:/accounting"}}

	assert.False(t, p1.actionEquals(p3.Actions))
}

func TestObjectInfo_equals(t *testing.T) {
	policies := getPolicies()
	p1 := policies.Policies[0]
	p2 := policies.Policies[1]
	assert.True(t, p1.Object.equals(&p2.Object))
	p3 := p1
	p3.Object.ResourceID = "abc"
	assert.False(t, p1.Object.equals(&p3.Object))
}

func TestConditionInfo_Equals(t *testing.T) {
	policies := getPolicies()
	p1 := policies.Policies[0]
	p2 := policies.Policies[1]
	assert.False(t, p1.Condition.Equals(p2.Condition))

	p3 := p1

	assert.True(t, p1.Condition.Equals(p3.Condition))
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
	policies := getPolicies()

	p1 := policies.Policies[0]
	etag := p1.CalculateEtag()

	assert.Equal(t, etag, p1.Meta.Etag)

	pnew := p1
	pnew.Object.ResourceID = "abc"
	etag2 := pnew.CalculateEtag()

	assert.NotEqual(t, etag, etag2, "Should be different etags")
}

func TestPolicyInfo_Equals(t *testing.T) {
	policies := getPolicies()

	p3 := policies.Policies[0]
	// This will be used to make sure subject is case insensitive
	p3.Subject = SubjectInfo{Members: []string{"Accounting@Hexaindustries.io"}}

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
			name:   "Subject case test",
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
	policies := getPolicies()

	p3 := policies.Policies[0]
	// This will be used to make sure subject is case insensitive
	p3.Subject = SubjectInfo{Members: []string{"Accounting@Hexaindustries.io"}}

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
			name:   "Subject case test",
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
	policyString := `
{
 "Meta": {
  "Etag": "20-0ec0e45955c6490a371dc2b111c46fbf1effb291",
  "PolicyId": "abc"
 },
 "Subject": {
  "Members": [
   "user1"
  ]
 },
 "Actions": [
  {
   "ActionUri": "actionUri"
  }
 ],
 "Object": {
  "resource_id": "aresource"
 }
}`
	testPolicy := PolicyInfo{
		Meta:      MetaInfo{PolicyId: &pid},
		Subject:   SubjectInfo{Members: []string{"user1"}},
		Actions:   []ActionInfo{{ActionUri: "actionUri"}},
		Object:    ObjectInfo{ResourceID: "aresource"},
		Condition: nil,
	}
	testPolicy.CalculateEtag()

	type fields struct {
		Type          string
		PolicyId      string
		Hash          string
		DifTypes      []string
		PolicyExist   *[]PolicyInfo
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
 "Meta": {
  "Etag": "20-0ec0e45955c6490a371dc2b111c46fbf1effb291",
  "PolicyId": "abc"
 },
 "Subject": {
  "Members": [
   "user1"
  ]
 },
 "Actions": [
  {
   "ActionUri": "actionUri"
  }
 ],
 "Object": {
  "resource_id": "aresource"
 }
}`
	testPolicy := PolicyInfo{
		Meta:      MetaInfo{PolicyId: &pid},
		Subject:   SubjectInfo{Members: []string{"user1"}},
		Actions:   []ActionInfo{{ActionUri: "actionUri"}},
		Object:    ObjectInfo{ResourceID: "aresource"},
		Condition: nil,
	}
	testPolicy.CalculateEtag()

	assert.Equal(t, policyString, testPolicy.String(), "String check")
}

func TestReconcilePolicies(t *testing.T) {
	policies := getPolicies()

	matchingPolicies := getPolicies()

	policiesWithIds := getPolicies()
	policiesIdSame := getPolicies()

	policiesWithChangesIds := getPolicies()

	policiesWithChangesHash := getPolicies()

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

	policiesWithChangesIds.Policies[0].Object.ResourceID = "changed"
	policiesWithChangesIds.Policies[0].CalculateEtag()
	assert.NotEqual(t, policiesWithIds.Policies[0].Object.ResourceID, "changed")

	policiesWithChangesHash.Policies[0].Object.ResourceID = "anotherchange"
	policiesWithChangesHash.Policies[0].CalculateEtag()

	policiesEmpty := Policies{
		Policies: []PolicyInfo{},
		App:      nil,
	}
	/*
		{
		      "meta": {
		        "version": "0.6"
		      },
		      "actions": [
		        {
		          "actionuri": "http:GET:/humanresources"
		        }
		      ],
		      "subject": {
		        "members": [
		          "humanresources@hexaindustries.io"
		        ]
		      },
		      "object": {
		        "resource_id": "aResourceId"
		      }
		    }`
	*/
	npid := "zyx"
	newPolicy := PolicyInfo{
		Meta: MetaInfo{
			Version:  IdqlVersion,
			PolicyId: &npid,
		},
		Subject: SubjectInfo{Members: []string{"phil.hunt@independentid.com"}},
		Actions: []ActionInfo{{ActionUri: "http:GET:/admin"}, {ActionUri: "http:POST:/admin"}},
		Object:  ObjectInfo{ResourceID: "hexaindustries"},
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
					PolicyExist:   &[]PolicyInfo{policiesWithIds.Policies[0]},
					PolicyCompare: &policiesIdSame.Policies[0],
				},
				{
					Type:          ChangeTypeEqual,
					PolicyId:      pid2,
					DifTypes:      []string{CompareEqual},
					PolicyExist:   &[]PolicyInfo{policiesWithIds.Policies[1]},
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
					PolicyExist:   &[]PolicyInfo{policies.Policies[0]},
					PolicyCompare: &matchingPolicies.Policies[0],
				},
				{
					Type:          ChangeTypeEqual,
					Hash:          policies.Policies[1].Meta.Etag,
					DifTypes:      []string{CompareEqual},
					PolicyExist:   &[]PolicyInfo{policies.Policies[1]},
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
				PolicyExist:   &[]PolicyInfo{policiesWithIds.Policies[0]},
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
				},
				{
					Type:        ChangeTypeDelete,
					Hash:        policies.Policies[0].CalculateEtag(),
					PolicyExist: &[]PolicyInfo{policies.Policies[0]},
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
				},
				{
					Type:          ChangeTypeNew,
					Hash:          policiesWithChangesHash.Policies[1].CalculateEtag(),
					PolicyExist:   nil,
					PolicyCompare: &policiesWithChangesHash.Policies[1],
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
					Hash:          policies.Policies[0].CalculateEtag(),
					PolicyExist:   &[]PolicyInfo{policies.Policies[0]},
					PolicyCompare: nil,
				},
				{
					Type:          ChangeTypeDelete,
					Hash:          policies.Policies[1].Meta.Etag,
					PolicyExist:   &[]PolicyInfo{policies.Policies[1]},
					PolicyCompare: nil,
				},
			},
		},
		{
			name: "Empty Set Compare with id (causes delete)",
			args: args{
				existingPolicies: policiesWithIds,
				comparePolicies:  policiesEmpty.Policies,
				diffsOnly:        true,
			},
			want: []PolicyDif{
				{
					Type:          ChangeTypeDelete,
					PolicyId:      *policiesWithIds.Policies[0].Meta.PolicyId,
					PolicyExist:   &[]PolicyInfo{policiesWithIds.Policies[0]},
					PolicyCompare: nil,
				},
				{
					Type:          ChangeTypeDelete,
					PolicyId:      *policiesWithIds.Policies[1].Meta.PolicyId,
					PolicyExist:   &[]PolicyInfo{policiesWithIds.Policies[1]},
					PolicyCompare: nil,
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
				},
				{
					Type:          ChangeTypeDelete,
					PolicyId:      *policiesWithIds.Policies[1].Meta.PolicyId,
					PolicyExist:   &[]PolicyInfo{policiesWithIds.Policies[1]},
					PolicyCompare: nil,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.existingPolicies.ReconcilePolicies(tt.args.comparePolicies, tt.args.diffsOnly)

			assert.Equalf(t, tt.want, got, "ReconcilePolicies(%v, %v, %v)", tt.args.existingPolicies, tt.args.comparePolicies, tt.args.diffsOnly)
		})
	}
}
