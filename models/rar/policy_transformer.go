package rar

import (
    "sort"
    "strings"

    "github.com/hexa-org/policy-mapper/models/rar/functionalsupport"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"

    "golang.org/x/exp/slices"
    log "golang.org/x/exp/slog"
)

const ActionUriPrefix = "http:"

func BuildPolicies(resourceActionRolesList []ResourceActionRoles) []hexapolicy.PolicyInfo {
    policies := make([]hexapolicy.PolicyInfo, 0)
    for _, one := range resourceActionRolesList {
        httpMethod := one.Action
        roles := one.Roles
        slices.Sort(roles)
        policies = append(policies, hexapolicy.PolicyInfo{
            Meta:     hexapolicy.MetaInfo{Version: hexapolicy.IdqlVersion, ProviderType: "RARmodel"},
            Actions:  []hexapolicy.ActionInfo{hexapolicy.ActionInfo(ActionUriPrefix + httpMethod)},
            Subjects: roles,
            Object:   hexapolicy.ObjectInfo(one.Resource),
        })
    }

    sortPolicies(policies)
    return policies
}

func FlattenPolicy(origPolicies []hexapolicy.PolicyInfo) []hexapolicy.PolicyInfo {

    resActionPolicyMap := make(map[string]hexapolicy.PolicyInfo)
    for _, pol := range origPolicies {
        resource := pol.Object
        if resource == "" {
            log.Warn("FlattenPolicy Skipping policy without resource")
            continue
        }
        for _, act := range pol.Actions {
            if strings.TrimSpace(string(act)) == "" {
                log.Warn("FlattenPolicy Skipping policy without actionUri", "resource", resource)
                continue
            }
            lookupKey := string(act) + resource.String()
            matchingPolicy, found := resActionPolicyMap[lookupKey]
            var existingMembers []string
            if found {
                existingMembers = matchingPolicy.Subjects
            }
            newMembers := CompactMembers(existingMembers, pol.Subjects)
            newPol := hexapolicy.PolicyInfo{
                Meta:     hexapolicy.MetaInfo{Version: hexapolicy.IdqlVersion},
                Actions:  []hexapolicy.ActionInfo{act},
                Subjects: newMembers,
                Object:   resource,
            }

            resActionPolicyMap[lookupKey] = newPol
        }
    }

    flat := make([]hexapolicy.PolicyInfo, 0)
    for _, pol := range resActionPolicyMap {
        flat = append(flat, pol)
    }

    sortPolicies(flat)
    return flat
}

func CompactActions(existing, new []hexapolicy.ActionInfo) []hexapolicy.ActionInfo {
    actionUris := make([]string, 0)
    for _, act := range existing {
        actionUris = append(actionUris, string(act))
    }
    for _, act := range new {
        actionUris = append(actionUris, string(act))
    }
    actionUris = functionalsupport.SortCompact(actionUris)

    actionInfos := make([]hexapolicy.ActionInfo, 0)
    for _, uri := range actionUris {
        actionInfos = append(actionInfos, hexapolicy.ActionInfo(uri))
    }
    return actionInfos
}

func CompactMembers(existing, new []string) []string {
    compacted := make([]string, 0)
    compacted = append(compacted, existing...)
    compacted = append(compacted, new...)
    return functionalsupport.SortCompact(compacted)
}

func sortPolicies(policies []hexapolicy.PolicyInfo) {
    sort.SliceStable(policies, func(i, j int) bool {
        resComp := strings.Compare(policies[i].Object.String(), policies[j].Object.String())
        actComp := strings.Compare(string(policies[i].Actions[0]), string(policies[j].Actions[0]))
        switch resComp {
        case 0:
            return actComp <= 0
        default:
            return resComp < 0

        }
    })
}

/*
// ResourcePolicyMap - makes a map of resource -> PolicyInfo
// If multiple PolicyInfo elements exist for a given resource, these are merged
// This ensures downstream functions do not have to deal with multiple policies for same resource.
// Also filters out any empty strings or duplicates in members or actions
func ResourcePolicyMap(origPolicies []hexapolicy.PolicyInfo) map[string]hexapolicy.PolicyInfo {
	resPolicyMap := make(map[string]hexapolicy.PolicyInfo)
	for _, pol := range origPolicies {
		resource := pol.Object.ResourceID

		var existingActions []hexapolicy.ActionInfo
		var existingMembers []string
		if existing, exists := resPolicyMap[resource]; exists {
			existingActions = existing.Actions
			existingMembers = existing.Subjects
		}

		mergedActions := CompactActions(existingActions, pol.Actions)
		newMembers := CompactMembers(existingMembers, pol.Subjects)

		newPol := hexapolicy.PolicyInfo{
			Meta:    hexapolicy.MetaInfo{Version: hexapolicy.IdqlVersion},
			Actions: mergedActions,
			Subjects: hexapolicy.SubjectInfo{Members: newMembers},
			Object:  hexapolicy.ObjectInfo{ResourceID: resource},
		}

		resPolicyMap[resource] = newPol

	}
	return resPolicyMap
}
*/
