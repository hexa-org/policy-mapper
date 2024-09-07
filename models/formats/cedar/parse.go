package cedar

import (
    "errors"
    "fmt"
    "strings"

    cedarParser "github.com/cedar-policy/cedar-go/x/exp/parser"
    "github.com/hexa-org/policy-mapper/models/conditionLangs/cedarConditions"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
)

/*
parse.go is needed to expose the internal Cedar parser for use by Hexa. In this package we leverage the Cedar Tokenizer
to build up the AST and Policy tree for mapping.
*/

type PolicyPair struct {
    HexaPolicy  *hexapolicy.PolicyInfo
    CedarPolicy *cedarParser.Policy
    res         strings.Builder
}

type ParseSet struct {
    IdqlPolicies    []hexapolicy.PolicyInfo
    Pairs           []PolicyPair
    Tokens          []cedarParser.Token
    Pos             int
    loc             string
    conditionMapper *cedarConditions.CedarConditionMapper
}

func MapCedarPolicyBytes(location string, cedarBytes []byte) (*hexapolicy.Policies, error) {

    tokens, err := cedarParser.Tokenize(cedarBytes)
    if err != nil {
        return nil, err
    }

    cset := ParseSet{
        Pairs:           make([]PolicyPair, 0),
        IdqlPolicies:    make([]hexapolicy.PolicyInfo, 0),
        Tokens:          tokens,
        Pos:             0,
        loc:             location,
        conditionMapper: &cedarConditions.CedarConditionMapper{},
    }

    res, err := cedarParser.Parse(tokens)
    for _, cedarPolicy := range res {
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

func (t *ParseSet) MapCedarPolicy(policy cedarParser.Policy) error {
    hexaPolicy := hexapolicy.PolicyInfo{}
    pair := PolicyPair{
        HexaPolicy:  &hexaPolicy,
        CedarPolicy: &policy,
    }

    var err error
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

func (t *ParseSet) MapHexaPolicy(policy hexapolicy.PolicyInfo) (string, error) {
    pp := PolicyPair{
        HexaPolicy: &policy,
        res:        strings.Builder{},
    }

    annotations := pp.mapHexaAnnotations()
    subjects := pp.mapHexaSubjects()
    actions := pp.mapHexaAction()
    resource := pp.mapHexaResource()

    conditions, err := t.conditionMapper.MapConditionToCedar(pp.HexaPolicy.Condition)
    if err != nil {
        return "", err
    }

    // conditions ;= pp.mapConditions()
    pp.writeCedarPolicy(annotations, subjects[0], actions, resource, conditions)
    return pp.res.String(), nil
}

func (pp *PolicyPair) writeCedarPolicy(annotations, subject, actions, resource, conditions string) {
    pp.res.WriteString(annotations)
    pp.res.WriteString("permit (\n  ")
    pp.res.WriteString(subject)
    pp.res.WriteString("\n  ")
    pp.res.WriteString(actions)
    pp.res.WriteString("\n  ")
    pp.res.WriteString(resource)
    pp.res.WriteString("\n)")
    pp.res.WriteString(conditions)
    pp.res.WriteString(";\n")

    return
}

// For Hexa, we just map annotations to Policy Meta
func (pp *PolicyPair) mapCedarAnnotations() {
    meta := pp.HexaPolicy.Meta
    if meta.SourceData == nil {
        meta.SourceData = make(map[string]interface{})
    }
    annotations := pp.CedarPolicy.Annotations
    if annotations == nil || len(annotations) == 0 {
        return
    }
    annotationMap := make(map[string]string)
    for _, annotation := range pp.CedarPolicy.Annotations {
        annotationMap[annotation.Key] = annotation.Value
    }
    meta.SourceData["annotations"] = annotationMap
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
        sb.WriteString(fmt.Sprintf("@%s(%s)\n", key, val))
    }
    return sb.String()
}

func (pp *PolicyPair) mapCedarSubject() {
    principal := pp.CedarPolicy.Principal

    paths := principal.Entity.Path

    var subj hexapolicy.SubjectInfo
    switch principal.Type {
    case cedarParser.MatchAny:
        subj = []string{hexapolicy.SubjectAnyUser}
    case cedarParser.MatchEquals:
        member := principal.Entity.String()
        // This is principal == xxx
        if len(paths) > 1 {
            member = fmt.Sprintf("%s:%s", paths[0], strings.Join(paths[1:], "::"))

        }
        subj = []string{member}
    case cedarParser.MatchIs:
        // This is "principal is User"
        // subj = []string{hexapolicy.SubjectAnyAuth}
        subj = []string{fmt.Sprintf("Type:%s", principal.Path.String())}
    case cedarParser.MatchIn:
        subj = []string{fmt.Sprintf("Group:%s", principal.Entity.String())}
    case cedarParser.MatchIsIn:
        isType := principal.Path.String()
        inEntity := strings.Replace(principal.Entity.String(), "::", ":", 1)
        subj = []string{fmt.Sprintf("%s.(%s)", inEntity, isType)}
    default:
        fmt.Println(fmt.Sprintf("Unexpected principal type: %T, value: %s", principal, principal.String()))
        subj = []string{principal.String()}
    }

    pp.HexaPolicy.Subjects = subj
}

func (pp *PolicyPair) HasMultiSubjects() bool {
    if pp.HexaPolicy != nil && pp.HexaPolicy.Subjects != nil {
        return len(pp.HexaPolicy.Subjects) > 0
    }
    return false
}

func (pp *PolicyPair) mapHexaSubjects() []string {
    if pp.HexaPolicy == nil || pp.HexaPolicy.Subjects != nil {
        return nil
    }
    members := pp.HexaPolicy.Subjects
    if len(members) == 0 || strings.EqualFold(members[0], hexapolicy.SubjectAnyUser) {
        return []string{"principal,"}
    }
    res := make([]string, 0)
    for _, member := range members {
        lower := strings.ToLower(member)
        if lower == "any" {
            res = append(res, "principal,")
            continue
        }
        if len(lower) < 5 {
            // not sure what this is, try principal == value
            res = append(res, fmt.Sprintf("principal == %s,", member))
            continue
        }
        switch lower[0:5] {
        case "anyauthenticated":
            res = append(res, "principal is User,")
        // case "user:":
        //    res = append(res, fmt.Sprintf("principal == User::%s,",member[6:]))
        case "group":
            value := member[5:]
            if strings.Contains(value, ".(") {
                parts := strings.Split(value, ".(")
                entity := parts[0]
                path := parts[1][0 : len(parts[1])-1]
                res = append(res, fmt.Sprintf(fmt.Sprintf("principal is %s in %s,", entity, path)))
            } else {
                // This is an in principal
                res = append(res, fmt.Sprintf(fmt.Sprintf("principal in %s,", value)))
            }

        case "domai":
            // todo - not sure what the cedar equivalence is
            res = append(res, "principal is User,")

        case "type:":
            res = append(res, fmt.Sprintf("principal is %s,", member[5:]))
        default:
            // assume this is principal == entity::"account" form
            firstColon := strings.Index(member, ":")
            res = append(res, fmt.Sprintf("principal == %s::%s,", member[0:firstColon], member[firstColon+1:]))
        }
    }
    return res
}

func (pp *PolicyPair) mapCedarAction() {
    action := pp.CedarPolicy.Action

    var aInfo []hexapolicy.ActionInfo
    switch action.Type {
    case cedarParser.MatchEquals:
        aInfo = append(aInfo, hexapolicy.ActionInfo(mapCedarEntityName(action.Entities[0])))
    case cedarParser.MatchIn:
        aInfo = append(aInfo, hexapolicy.ActionInfo("Role:"+mapCedarEntityName(action.Entities[0])))
    case cedarParser.MatchInList:
        for _, entity := range action.Entities {
            aInfo = append(aInfo, hexapolicy.ActionInfo(mapCedarEntityName(entity)))
        }
    default:
        fmt.Println(fmt.Sprintf("Unexpected action type: %T, value: %s", action, action.String()))
        aInfo = append(aInfo, hexapolicy.ActionInfo(action.String()))
    }

    pp.HexaPolicy.Actions = aInfo
}

func (pp *PolicyPair) mapHexaAction() string {
    actions := pp.HexaPolicy.Actions
    if actions == nil || len(actions) == 0 {
        return "action,"
    }
    if len(actions) == 1 {
        // if action has a prefix of "Role" then the value is action in xxx
        value := string(actions[0])
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
        sb.WriteString(string(e))
    }
    sb.WriteString("],")
    return sb.String()
}

func mapCedarEntityName(entity cedarParser.Entity) string {
    paths := entity.Path
    if len(paths) < 2 {
        return entity.String()
    }

    // Drop the Action

    if paths[0] == "Action" {
        if len(paths) > 2 {
            return fmt.Sprintf(
                "%s::%q",
                strings.Join(paths[1:len(paths)-1], "::"),
                paths[len(paths)-1],
            )

        }
        return paths[1]
    }

    return entity.String()
}

func (pp *PolicyPair) mapCedarResource() {
    resource := pp.CedarPolicy.Resource
    switch resource.Type {
    case cedarParser.MatchEquals:
        pp.HexaPolicy.Object = hexapolicy.ObjectInfo(resource.Entity.String())
    case cedarParser.MatchAny:
        pp.HexaPolicy.Object = ""
    case cedarParser.MatchIs:
        pp.HexaPolicy.Object = hexapolicy.ObjectInfo(fmt.Sprintf("Type:%s", resource.Path.String()))
    case cedarParser.MatchIsIn:
        pp.HexaPolicy.Object = hexapolicy.ObjectInfo(fmt.Sprintf("[%s].(%s)", resource.Entity.String(), resource.Path.String()))
    case cedarParser.MatchIn:
        pp.HexaPolicy.Object = hexapolicy.ObjectInfo(fmt.Sprintf("[%s]", resource.Entity.String()))
    default:
        fmt.Println(fmt.Sprintf("Unexpected resource type: %T, value: %s", resource, resource.String()))
        pp.HexaPolicy.Object = hexapolicy.ObjectInfo(fmt.Sprintf("[%s]", resource.String()))
    }
}

func (pp *PolicyPair) mapHexaResource() string {
    resource := pp.HexaPolicy.Object.String()
    if resource == "" {
        return "resource"
    }
    if strings.HasPrefix(strings.ToLower(resource), "type:") {
        return fmt.Sprintf("resource is %s", resource[5:])
    }
    if !strings.HasPrefix(resource, "[") {
        return fmt.Sprintf("resource == %s", resource)
    }
    if !strings.Contains(resource, ".(") {
        // this is [entity].(typepath)
        entity := resource[1:strings.Index(resource, "]")]
        path := resource[strings.Index(resource, ".(")+2 : len(resource)-1]

        return fmt.Sprintf("resource is %s in %s", path, entity)
    }
    // this is [Entity]
    return fmt.Sprintf("resource in %s", resource[1:len(resource)-1])
}

func (pp *PolicyPair) mapCedarConditions() error {
    hexaCondition, err := cedarConditions.MapCedarConditionToHexa(pp.CedarPolicy.Conditions)
    if hexaCondition != nil {
        pp.HexaPolicy.Condition = hexaCondition
    }
    return err
}
