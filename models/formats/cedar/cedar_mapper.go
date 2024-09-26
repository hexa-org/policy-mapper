package cedar

import (
    "encoding/json"
    "errors"
    "fmt"
    "strings"

    "github.com/cedar-policy/cedar-go"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"

    "github.com/hexa-org/policy-mapper/models/conditionLangs/cedarConditions"
    policyjson "github.com/hexa-org/policy-mapper/models/formats/cedar/json"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
)

type CedarMapper struct {
    condMap *cedarConditions.CedarConditionMapper
}

func NewCedarMapper(attrNameMap map[string]string) *CedarMapper {
    return &CedarMapper{condMap: &cedarConditions.CedarConditionMapper{conditions.NewNameMapper(attrNameMap)}}
}

/*
cedar_mapper.go is needed to expose the internal Cedar parser for use by Hexa. In this package we leverage the Cedar Tokenizer
to build up the AST and Policy tree for mapping.
*/

type PolicyPair struct {
    HexaPolicy  *hexapolicy.PolicyInfo
    CedarPolicy *cedar.Policy
    Ast         policyjson.PolicyJSON
    res         strings.Builder
}

type ParseSet struct {
    IdqlPolicies []hexapolicy.PolicyInfo
    Pairs        []PolicyPair

    Pos             int
    loc             string
    conditionMapper *cedarConditions.CedarConditionMapper
}

func (c *CedarMapper) MapCedarPolicyBytes(location string, cedarBytes []byte) (*hexapolicy.Policies, error) {

    policies, err := cedar.NewPolicyListFromBytes(location, cedarBytes)
    if err != nil {
        return nil, err
    }
    cset := ParseSet{
        Pairs:           make([]PolicyPair, 0),
        IdqlPolicies:    make([]hexapolicy.PolicyInfo, 0),
        Pos:             0,
        loc:             location,
        conditionMapper: c.condMap,
    }

    for _, cedarPolicy := range policies {
        err := cset.MapCedarPolicy(cedarPolicy)
        if err != nil {
            break
        }

    }

    return &hexapolicy.Policies{
        Policies: cset.IdqlPolicies,
        App:      &location,
    }, err

}

func (t *ParseSet) MapCedarPolicy(policy *cedar.Policy) error {
    var err error
    hexaPolicy := hexapolicy.PolicyInfo{Meta: hexapolicy.MetaInfo{Version: hexapolicy.IdqlVersion}}

    jsonBytes, err := policy.MarshalJSON()
    if err != nil {
        return err
    }

    var jsonPolicy policyjson.PolicyJSON

    err = json.Unmarshal(jsonBytes, &jsonPolicy)
    if err != nil {
        return err
    }
    pair := PolicyPair{
        HexaPolicy:  &hexaPolicy,
        CedarPolicy: policy,
        Ast:         jsonPolicy,
    }

    pair.mapCedarAnnotations()
    pair.mapCedarSubject()
    pair.mapCedarAction()
    pair.mapCedarResource()
    err = pair.mapCedarConditions()

    if err != nil {
        return err
    }

    if pair.HexaPolicy != nil {
        t.IdqlPolicies = append(t.IdqlPolicies, *pair.HexaPolicy)
    } else {
        return errors.New("no policy mapped")
    }

    return nil
}

func (c *CedarMapper) MapHexaPolicyBytes(location string, idqlBytes []byte) (string, error) {
    policies, err := hexapolicysupport.ParsePolicies(idqlBytes)
    if err != nil {
        return "", err
    }
    return c.MapHexaPolicies(location, policies)
}

func (c *CedarMapper) MapHexaPolicies(location string, policies []hexapolicy.PolicyInfo) (string, error) {
    sb := strings.Builder{}
    pset := ParseSet{
        Pairs:           make([]PolicyPair, 0),
        IdqlPolicies:    make([]hexapolicy.PolicyInfo, 0),
        Pos:             0,
        loc:             location,
        conditionMapper: c.condMap,
    }

    for _, hexaPolicy := range policies {
        cedarPol, err := pset.MapHexaPolicy(hexaPolicy)
        if err != nil {
            return "", err
        }

        sb.WriteString(cedarPol)

    }

    return sb.String(), nil
}

func (t *ParseSet) MapHexaPolicy(policy hexapolicy.PolicyInfo) (string, error) {
    pp := PolicyPair{
        HexaPolicy: &policy,
        res:        strings.Builder{},
    }

    annotations := pp.mapHexaAnnotations()
    subjects := pp.mapHexaSubjects()
    actions := pp.mapHexaAction()
    resource := pp.mapHexaResource()

    condition, err := t.conditionMapper.MapConditionToCedar(pp.HexaPolicy.Condition)
    if err != nil {
        return "", err
    }

    // conditions ;= pp.mapConditions()
    for _, subject := range subjects {
        pp.writeCedarPolicy(annotations, subject, actions, resource, condition)
    }

    return pp.res.String(), nil
}

func (pp *PolicyPair) writeCedarPolicy(annotations, subject, actions, resource, conditions string) {
    pp.res.WriteString(annotations)
    // Note: IDQL policies are always a permit
    pp.res.WriteString("permit (\n  ")
    pp.res.WriteString(subject)
    pp.res.WriteString("\n  ")
    pp.res.WriteString(actions)
    pp.res.WriteString("\n  ")
    pp.res.WriteString(resource)
    pp.res.WriteString("\n)")
    if conditions != "" {
        pp.res.WriteString("\n")
        pp.res.WriteString(conditions)
    }

    pp.res.WriteString(";\n")

    return
}

// For Hexa, we just map annotations to Policy Meta
func (pp *PolicyPair) mapCedarAnnotations() {
    meta := pp.HexaPolicy.Meta

    annotations := pp.CedarPolicy.Annotations
    aMap := annotations()
    if aMap == nil || len(aMap) == 0 {
        return
    }
    if meta.SourceData == nil {
        meta.SourceData = make(map[string]interface{})
    }
    meta.SourceData["annotations"] = aMap
    pp.HexaPolicy.Meta = meta
}

func (pp *PolicyPair) mapHexaAnnotations() string {
    meta := pp.HexaPolicy.Meta
    sourceData := meta.SourceData
    if sourceData == nil {
        return ""
    }
    annotationMap, ok := sourceData["annotations"].(map[string]interface{})
    if !ok {
        return ""
    }
    sb := strings.Builder{}
    for key, val := range annotationMap {
        sb.WriteString(fmt.Sprintf("@%s(\"%s\")\n", key, val))
    }
    return sb.String()
}

func mapCedarScope(isSubj bool, scope policyjson.ScopeJSON) []string {
    switch scope.Op {
    case "All":
        if isSubj {
            return []string{hexapolicy.SubjectAnyUser}
        }
        return []string{}
    case "==":
        if isSubj {
            return []string{fmt.Sprintf("%s:%s", scope.Entity.Type, scope.Entity.ID)}
        }
        return []string{fmt.Sprintf("%s::%s", scope.Entity.Type, scope.Entity.ID)}
    case "is":
        // This is "principal is User"
        // subj = []string{hexapolicy.SubjectAnyAuth}
        if scope.In != nil {
            // is in
            isType := scope.EntityType
            inEntity := fmt.Sprintf("%s::%s", scope.In.Entity.Type, scope.In.Entity.ID)
            return []string{fmt.Sprintf("Type:%s[%s]", isType, inEntity)}
        } else {
            return []string{fmt.Sprintf("Type:%s", scope.EntityType)}
        }

    case "in":
        if scope.Entity != nil {
            return []string{fmt.Sprintf("[%s::%s]", scope.Entity.Type, scope.Entity.ID)}
        } else {
            items := make([]string, len(scope.Entities))
            for i, entity := range scope.Entities {
                items[i] = fmt.Sprintf("%s::%s", entity.Type, entity.ID)
            }
            return items
        }

    }
    return []string{}
}

func (pp *PolicyPair) mapCedarSubject() {

    principal := pp.Ast.Principal

    subjs := mapCedarScope(true, principal)
    if len(subjs) == 0 {
        subjs = hexapolicy.SubjectInfo{hexapolicy.SubjectAnyUser}
    }
    pp.HexaPolicy.Subjects = subjs
}

func mapHexaValue(verb string, member string) string {
    if verb == "principal" {
        if strings.EqualFold(member, "any") {
            return "principal,"
        }
        if strings.EqualFold(member, "anyAuthenticated") {
            return "principal is User,"
        }
    }
    comma := ","
    if verb == "resource" {
        comma = ""
    }
    if member == "" {
        return fmt.Sprintf("%s%s", verb, comma)
    }
    // check for is type
    if strings.HasPrefix(member, "Type:") {
        entity := member[5:]
        if strings.Contains(entity, "[") {
            openIndex := strings.Index(entity, "[")
            isType := entity[0:openIndex]
            inEntity := mapHexaToCedarValue(entity[openIndex+1 : len(entity)-1])
            return fmt.Sprintf("%s is %s in %s%s", verb, isType, inEntity, comma)
        } else {
            return fmt.Sprintf("%s is %s%s", verb, entity, comma)
        }
    }
    // Check for "in" type
    if strings.HasPrefix(member, "[") {
        return fmt.Sprintf("%s in %s%s", verb, mapHexaToCedarValue(member[1:len(member)-1]), comma)
    }
    // assume it is an ==

    memberFix := mapHexaToCedarValue(member)

    return fmt.Sprintf("%s == %s%s", verb, memberFix, comma)
}

func mapHexaToCedarValue(item string) string {
    item = strings.Replace(item, "::", ":", -1)
    itemComps := strings.Split(item, ":")
    eId := itemComps[len(itemComps)-1]
    eType := itemComps[0]
    if len(itemComps) > 2 { // handles the case TestApp::Photos::"vacationPhoto.jpg"
        eType = strings.Join(itemComps[0:len(itemComps)-2], "::")
    }
    itemFix := item
    if len(itemComps) >= 2 {
        itemFix = fmt.Sprintf("%s::\"%s\"", eType, eId)
    }
    return itemFix
}

func (pp *PolicyPair) mapHexaSubjects() []string {
    if pp.HexaPolicy == nil || pp.HexaPolicy.Subjects == nil {
        return nil
    }
    members := pp.HexaPolicy.Subjects
    if len(members) == 0 || strings.EqualFold(members[0], hexapolicy.SubjectAnyUser) {
        return []string{"principal,"}
    }
    res := make([]string, 0)
    for _, member := range members {
        res = append(res, mapHexaValue("principal", member))
    }
    return res
}

func (pp *PolicyPair) mapCedarAction() {
    action := pp.Ast.Action

    values := mapCedarScope(false, action)

    actions := make([]hexapolicy.ActionInfo, len(values))
    for i, value := range values {
        actions[i] = hexapolicy.ActionInfo(value)
    }
    pp.HexaPolicy.Actions = actions
}

func (pp *PolicyPair) mapHexaAction() string {
    actions := pp.HexaPolicy.Actions
    if actions == nil || len(actions) == 0 {
        return "action,"
    }
    if len(actions) == 1 {
        // if action has a prefix of "Role" then the value is action in xxx
        value := mapHexaToCedarValue(string(actions[0]))
        if strings.HasPrefix(strings.ToLower(value), "role:") {
            return fmt.Sprintf("action in %s,", value[5:])
        }
        return fmt.Sprintf("action == %s,", value)
    }
    var sb strings.Builder
    sb.WriteString("action in [")
    for i, e := range actions {
        if i > 0 {
            sb.WriteString(",")
        }
        sb.WriteString(mapHexaToCedarValue(string(e)))
    }
    sb.WriteString("],")
    return sb.String()
}

func (pp *PolicyPair) mapCedarResource() {
    resource := pp.Ast.Resource

    values := mapCedarScope(false, resource)
    if values == nil || len(values) == 0 {
        pp.HexaPolicy.Object = hexapolicy.ObjectInfo("")
    } else {
        pp.HexaPolicy.Object = hexapolicy.ObjectInfo(values[0])
    }

}

func (pp *PolicyPair) mapHexaResource() string {
    resource := pp.HexaPolicy.Object.String()

    return mapHexaValue("resource", resource)

}

func (pp *PolicyPair) mapCedarConditions() error {
    hexaCondition, err := cedarConditions.MapCedarConditionToHexa(pp.Ast.Conditions)
    if hexaCondition != nil {
        pp.HexaPolicy.Condition = hexaCondition
    }
    return err
}
