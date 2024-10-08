package policytestsupport

import (
    "fmt"
    "reflect"
    "sort"
    "testing"

    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
    "github.com/stretchr/testify/assert"
)

func ContainsPolicies(t *testing.T, expPolicies []hexapolicy.PolicyInfo, actPolicies []hexapolicy.PolicyInfo) bool {
    for _, act := range actPolicies {
        if HasPolicy(expPolicies, act) {
            return true
        }
    }

    return assert.Fail(t, fmt.Sprintf("Policies do not match expected: \n expected: %v\n actual: %v", expPolicies, actPolicies))
}

func HasPolicy(expPolicies []hexapolicy.PolicyInfo, act hexapolicy.PolicyInfo) bool {
    for _, exp := range expPolicies {
        if MatchPolicy(exp, act) {
            return true
        }
    }
    return false
}

func MatchPolicy(exp hexapolicy.PolicyInfo, act hexapolicy.PolicyInfo) bool {
    if exp.Object.String() != act.Object.String() {
        return false
    }

    expActions := sortAction(exp.Actions)
    actActions := sortAction(act.Actions)
    if !reflect.DeepEqual(expActions, actActions) {
        return false
    }

    expMembers := sortMembers(exp.Subjects)
    actMembers := sortMembers(act.Subjects)
    return reflect.DeepEqual(expMembers, actMembers)
}

func MakePolicies(actionMembers map[string][]string, resourceId string) []hexapolicy.PolicyInfo {
    policies := make([]hexapolicy.PolicyInfo, 0)

    for action, membersNoPrefix := range actionMembers {
        members := make([]string, 0)
        for _, mem := range membersNoPrefix {
            members = append(members, "user:"+mem)
        }

        pol := hexapolicy.PolicyInfo{
            Meta:     hexapolicy.MetaInfo{Version: hexapolicy.IdqlVersion},
            Actions:  []hexapolicy.ActionInfo{hexapolicy.ActionInfo(action)},
            Subjects: members,
            Object:   hexapolicy.ObjectInfo(resourceId),
        }

        policies = append(policies, pol)
    }

    return policies
}

func sortAction(orig []hexapolicy.ActionInfo) []hexapolicy.ActionInfo {
    sorted := make([]hexapolicy.ActionInfo, 0)
    sorted = append(sorted, orig...)
    sort.Slice(sorted, func(i, j int) bool {
        return sorted[i] <= sorted[j]
    })
    return sorted
}

func sortMembers(subInfo hexapolicy.SubjectInfo) hexapolicy.SubjectInfo {
    sorted := make([]string, 0)
    for _, one := range subInfo {
        sorted = append(sorted, one)
    }
    sort.Strings(sorted)
    return sorted
}
