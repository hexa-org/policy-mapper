package policytestsupport

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hexa-org/policy-mapper/models/rar"
)

func MakeRarList(retActionRoles map[string][]string) []rar.ResourceActionRoles {
	rarList := make([]rar.ResourceActionRoles, 0)

	for actionAndRes, roles := range retActionRoles {
		resRole := MakeRar(actionAndRes, roles)
		rarList = append(rarList, resRole)
	}

	sort.SliceStable(rarList, func(i, j int) bool {
		a := rarList[i]
		b := rarList[j]
		resComp := strings.Compare(a.Resource, b.Resource)
		actComp := strings.Compare(a.Action, b.Action)
		switch resComp {
		case 0:
			return actComp <= 0
		default:
			return resComp < 0
		}
	})

	/*slices.SortStableFunc(rarList, func(a, b rar.ResourceActionRoles) bool {
		resComp := strings.Compare(a.Resource, b.Resource)
		actComp := strings.Compare(a.Action, b.Action)
		switch resComp {
		case 0:
			return actComp <= 0
		default:
			return resComp < 0
		}
	})*/
	return rarList
}

func MakeRar(actionAndRes string, roles []string) rar.ResourceActionRoles {
	parts := strings.Split(actionAndRes, "/")
	resActionKey := fmt.Sprintf("resrol-http%s-%s", strings.ToLower(parts[0]), strings.Join(parts[1:], "-"))
	return rar.NewResourceActionRolesFromProviderValue(resActionKey, roles)
}
