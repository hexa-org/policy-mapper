// Package awsCedar provides parsing and mapping to and from an earlier version of AWS Cedar Policy Language
//
// Deprecated: This package has been deprecated and is replaced by /models/formats/cedar.
//
// This package will be removed shortly in a future update.
package awsCedar

import (
    "errors"
    "fmt"
    "os"
    "strings"

    "github.com/alecthomas/participle/v2"
    "github.com/hexa-org/policy-mapper/models/conditionLangs/gcpcel"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
    policyCond "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
)

type CedarPolicyMapper struct {
    ConditionMapper gcpcel.GoogleConditionMapper
    Parser          *participle.Parser[CedarPolicies]
}

// New opens an instance of the CedarPolicyMapper. If nameMap is provided attribute
// names in conditions will be converted in the form [hexaName]cedarName.
// Deprecated: This mapper has been replaced by the cedar-go version in https://github.com/hexa-org/policy-mapper/models/formats/cedar
func New(nameMap map[string]string) *CedarPolicyMapper {
    return &CedarPolicyMapper{ConditionMapper: gcpcel.GoogleConditionMapper{NameMapper: policyCond.NewNameMapper(nameMap)},
        Parser: participle.MustBuild[CedarPolicies](participle.CaseInsensitive("permit", "forbid", "unless", "when"))}
}

func (c *CedarPolicyMapper) ParseCedarBytes(cedarBytes []byte) (*CedarPolicies, error) {
    cedarAst, err := c.Parser.ParseBytes("", cedarBytes)
    return cedarAst, err
}

func (c *CedarPolicyMapper) Name() string {
    return "cedar"
}

/*
MapPolicyToCedar takes an IDQL Policy and maps it to 1 or more Cedar policies. The need for more than one arises because
IDQL supports multiple subjects where Cedar is limited to 1 Principal and 1 Resource.
*/
func (c *CedarPolicyMapper) MapPolicyToCedar(idqlPol hexapolicy.PolicyInfo) ([]*CedarPolicy, error) {
    cpolicies := make([]*CedarPolicy, 0)

    if len(idqlPol.Subjects) == 0 {
        cpolicy, err := c.mapSimplePolicyToCedar("", idqlPol)
        if err != nil {
            return nil, err
        }
        cpolicies = append(cpolicies, cpolicy)

        return cpolicies, nil
    }

    for _, v := range idqlPol.Subjects {
        cpolicy, err := c.mapSimplePolicyToCedar(v, idqlPol)
        if err != nil {
            return nil, err
        }
        cpolicies = append(cpolicies, cpolicy)
    }
    return cpolicies, nil
}

func removeLastQuotes(item string) string {
    ret := item

    elems := strings.Split(item, "::")
    lastItemIndex := len(elems) - 1
    lastItem := elems[lastItemIndex]
    if lastItem[0:1] == "\"" {
        elems[lastItemIndex] = lastItem[1 : len(lastItem)-1]
    }
    ret = elems[0]
    for i, elem := range elems {
        if i > 0 {
            ret = ret + "::" + elem
        }
    }

    return ret
}

func mapActionItemToUri(cedarAction string) string {
    ret := cedarAction
    if strings.Contains(cedarAction, "::") {

        // Because IDQL represents values in JSON, get rid of the extra quotes

        ret = "cedar:" + removeLastQuotes(cedarAction)
    }
    return ret
}

func addLastQuotes(item string) string {
    elems := strings.Split(item, "::")
    lastitemindex := len(elems) - 1
    lastitem := elems[lastitemindex]

    if lastitem[0:1] != "\"" {
        // Add double quotes if missing
        elems[lastitemindex] = "\"" + lastitem + "\""
    }

    ret := elems[0]
    for i, elem := range elems {
        if i > 0 {
            ret = ret + "::" + elem
        }
    }
    return ret
}

func mapActionUri(idqlaction string) string {
    ret := idqlaction
    // Cedar puts quotes around th eaction value, so we need to re-add them
    if strings.HasPrefix(strings.ToLower(idqlaction), "cedar:") {
        ret = idqlaction[6:]
    }

    return addLastQuotes(ret)
}

func (c *CedarPolicyMapper) mapActions(actions []hexapolicy.ActionInfo) *ActionExpression {
    switch len(actions) {
    case 0:
        return nil
    case 1:
        action := mapActionUri(string(actions[0]))

        return &ActionExpression{
            Operator: EQUALS,
            Action:   action,
        }

    default:
        cActions := make([]ActionItem, len(actions))
        for k, v := range actions {
            actionIden := mapActionUri(string(v))
            cActions[k].Item = actionIden
        }
        return &ActionExpression{
            Operator: IN,
            Actions:  cActions,
        }
    }
}

func isSingular(entityId string) bool {
    var singleResources = []string{"file", "user", "employee"}
    lEntityId := strings.ToLower(entityId)
    for _, v := range singleResources {
        if strings.HasPrefix(lEntityId, v) {
            return true
        }
    }
    return false
}

func mapResourceToObject(res *ResourceExpression) hexapolicy.ObjectInfo {
    mId := "cedar:" + removeLastQuotes(res.Entity)

    return hexapolicy.ObjectInfo(mId)
}

func mapObjectToResource(object hexapolicy.ObjectInfo) *ResourceExpression {
    id := object.String()
    if id == "" {
        return nil
    }
    op := IN
    if isSingular(id) {
        op = EQUALS
    }

    mId := id
    if strings.HasPrefix(strings.ToLower(id), "cedar:") {
        mId = id[6:]
    }
    return &ResourceExpression{
        Operator: op,
        Entity:   addLastQuotes(mId),
    }
}

func mapMemberToPrincipal(member string) string {
    parts := strings.SplitN(member, ":", 2)
    if len(parts) == 1 {
        return member
    }
    if strings.HasPrefix(parts[1], ":") {
        return member
    }

    return parts[0] + "::" + addLastQuotes(parts[1])
}

func mapPrincipalToMember(principal string) string {
    parts := strings.SplitN(principal, "::", 2)
    if len(parts) == 1 {
        return principal
    }

    return parts[0] + ":" + removeLastQuotes(parts[1])
}

func (c *CedarPolicyMapper) mapSimplePolicyToCedar(member string, policy hexapolicy.PolicyInfo) (*CedarPolicy, error) {
    var conds []*ConditionalClause
    if policy.Condition != nil {
        operator := WHEN
        if policy.Condition.Action == "deny" {
            operator = UNLESS
        }
        cel, err := c.ConditionMapper.MapConditionToProvider(*policy.Condition)
        if err != nil {
            return nil, err
        }
        var cond = ConditionType(cel)
        conds = append(conds, &ConditionalClause{
            Type:      operator,
            Condition: &cond,
        })
    }

    var principal *PrincipalExpression
    switch member {
    case hexapolicy.SubjectAnyUser, "":
        principal = nil

    case hexapolicy.SubjectAnyAuth, hexapolicy.SubjectJwtAuth, hexapolicy.SubjectSamlAuth, hexapolicy.SubjectBasicAuth:
        principal = nil
        cond := ConditionType("context.authenticated == true")
        conds = append(conds, &ConditionalClause{
            Type:      WHEN,
            Condition: &cond})
    default:
        princ := mapMemberToPrincipal(member)
        lMember := strings.ToLower(member)
        switch lMember[0:4] {
        case "user:":
            principal = &PrincipalExpression{
                Operator: "==",
                Entity:   princ,
            }
        case "group", "domai":
            principal = &PrincipalExpression{
                Operator: "in",
                Entity:   princ,
            }

        default:
            // For now assume all other types are singular so ==
            principal = &PrincipalExpression{
                Operator: "==",
                Entity:   princ,
            }

        }
    }

    actions := c.mapActions(policy.Actions)
    res := mapObjectToResource(policy.Object)

    head := PolicyHead{
        Principal: principal,
        Actions:   actions,
        Resource:  res,
    }

    return &CedarPolicy{
        Type:       PERMIT,
        Head:       &head,
        Conditions: conds,
    }, nil
}

func (c *CedarPolicyMapper) MapHexaPolicies(policies []hexapolicy.PolicyInfo) (map[string]interface{}, error) {
    pols, err := c.MapPoliciesToCedar(policies)
    return map[string]interface{}{"cedar": pols}, err
}

func (c *CedarPolicyMapper) MapToHexaPolicy(cedarpolicies map[string]interface{}) ([]hexapolicy.PolicyInfo, error) {
    pols := hexapolicy.Policies{
        Policies: []hexapolicy.PolicyInfo{},
    }
    var err error
    for _, v := range cedarpolicies {
        switch obj := v.(type) {
        case CedarPolicies:
            policies, err := c.MapCedarPoliciesToIdql(&obj)
            if err == nil && policies != nil {
                pols.AddPolicies(*policies)
            }

        case CedarPolicy:
            policyInfo, err := c.MapCedarPolicyToIdql(&obj)
            if err == nil && policyInfo != nil {
                pols.AddPolicy(*policyInfo)
            }

        case []byte:
            policies, err := c.ParseAndMapCedarToHexa(obj)
            if err == nil && policies != nil {
                pols.AddPolicies(*policies)
            }

        case string:
            policies, err := c.ParseFile(obj)
            if err == nil && policies != nil {
                pols.AddPolicies(*policies)
            }

        default:
            err = errors.New(fmt.Sprintf("Unsupported Cedar input type: %t", obj))
            break
        }
    }
    return pols.Policies, err
}

func (c *CedarPolicyMapper) MapPoliciesToCedar(policies []hexapolicy.PolicyInfo) (*CedarPolicies, error) {
    cpolicies := make([]*CedarPolicy, 0)
    for _, v := range policies {
        newPols, err := c.MapPolicyToCedar(v)
        if err != nil {
            return nil, err
        }
        cpolicies = append(cpolicies, newPols...)
    }

    return &CedarPolicies{
        Policies: cpolicies,
    }, nil
}

func (c *CedarPolicyMapper) MapCedarPolicyToIdql(policy *CedarPolicy) (*hexapolicy.PolicyInfo, error) {

    var subj hexapolicy.SubjectInfo
    if policy.Head.Principal == nil {
        subj = []string{hexapolicy.SubjectAnyUser}
    } else {
        subj = []string{mapPrincipalToMember(policy.Head.Principal.Entity)}
    }

    actions := make([]hexapolicy.ActionInfo, 0)
    if policy.Head.Actions != nil {
        if policy.Head.Actions.Action != "" {
            actions = append(actions, hexapolicy.ActionInfo(mapActionItemToUri(policy.Head.Actions.Action)))
        } else {
            for _, v := range policy.Head.Actions.Actions {
                actions = append(actions, hexapolicy.ActionInfo(mapActionItemToUri(v.Item)))
            }
        }
    }

    conditionsClauses := make([]string, 0)
    for _, v := range policy.Conditions {
        cel := string(*v.Condition)
        // cel mapTool won't tolerate ::
        if strings.Contains(cel, "::") {
            cel = strings.ReplaceAll(cel, "Group::\"", "\"Group:")
            cel = strings.ReplaceAll(cel, "User::\"", "\"User:")
            cel = strings.ReplaceAll(cel, "GitAccount::\"", "\"GitAccount:")
            cel = strings.ReplaceAll(cel, "Domain::\"", "\"Domain:")
            cel = strings.ReplaceAll(cel, "Account::\"", "\"Account:")
            // cel = strings.ReplaceAll(cel, " in ", " co ") // this is just temporary
        }
        if strings.EqualFold(cel, "true") {
            // just ignore it
            continue
        }

        idqlCond, err := c.ConditionMapper.MapProviderToCondition(cel)
        if err != nil {
            return nil, err
        }

        if v.Type == WHEN {
            conditionsClauses = append(conditionsClauses, idqlCond.Rule)
        } else {
            conditionsClauses = append(conditionsClauses, "not("+idqlCond.Rule+")")
        }
    }

    var condInfo *policyCond.ConditionInfo
    if len(conditionsClauses) == 0 {
        condInfo = nil
    } else {
        if len(conditionsClauses) == 1 {
            condInfo = &policyCond.ConditionInfo{
                Rule:   conditionsClauses[0],
                Action: PERMIT,
            }
        } else {
            merge := ""
            for i, v := range conditionsClauses {
                if i == 0 {
                    merge = "(" + v + ")"
                } else {
                    if strings.HasPrefix(v, "not") {
                        merge = merge + " && " + v
                    } else {
                        merge = merge + " && (" + v + ")"

                    }
                }
            }
            condInfo = &policyCond.ConditionInfo{
                Rule:   merge,
                Action: PERMIT,
            }
        }
    }

    var obj hexapolicy.ObjectInfo
    if policy.Head.Resource != nil {
        obj = mapResourceToObject(policy.Head.Resource)
    }
    ret := hexapolicy.PolicyInfo{
        Meta:      hexapolicy.MetaInfo{Version: hexapolicy.IdqlVersion},
        Actions:   actions,
        Subjects:  subj,
        Object:    obj,
        Condition: condInfo,
    }
    return &ret, nil
}

func (c *CedarPolicyMapper) MapCedarPoliciesToIdql(cedarPols *CedarPolicies) (*hexapolicy.Policies, error) {
    pols := make([]hexapolicy.PolicyInfo, 0)

    for _, v := range cedarPols.Policies {
        mapPol, err := c.MapCedarPolicyToIdql(v)
        if err != nil {
            return nil, err
        }
        pols = append(pols, *mapPol)
    }
    return &hexapolicy.Policies{Policies: pols}, nil
}

func (c *CedarPolicyMapper) ParseFile(filename string) (*hexapolicy.Policies, error) {
    policyBytes, err := os.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    return c.ParseAndMapCedarToHexa(policyBytes)
}

func (c *CedarPolicyMapper) ParseAndMapCedarToHexa(cedarBytes []byte) (*hexapolicy.Policies, error) {

    cedarPols, err := c.ParseCedarBytes(cedarBytes)
    if err != nil {
        return nil, err
    }

    return c.MapCedarPoliciesToIdql(cedarPols)
}
