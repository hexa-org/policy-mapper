package cognitoProvider

import (
    "net/http"
    "strings"

    "github.com/hexa-org/policy-mapper/api/policyprovider"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
    "github.com/hexa-org/policy-mapper/providers/aws/awscognito"
    "github.com/hexa-org/policy-mapper/providers/aws/awscommon"

    "github.com/go-playground/validator/v10"
)

const ProviderTypeAwsCognito string = "cognito"

type CognitoProvider struct {
    AwsClientOpts awscommon.AWSClientOptions
}

func (a *CognitoProvider) Name() string {
    return ProviderTypeAwsCognito
}

func (a *CognitoProvider) DiscoverApplications(info policyprovider.IntegrationInfo) ([]policyprovider.ApplicationInfo, error) {
    if !strings.EqualFold(info.Name, a.Name()) {
        return []policyprovider.ApplicationInfo{}, nil
    }

    client, err := awscognito.NewCognitoClient(info.Key, a.AwsClientOpts)
    if err != nil {
        return nil, err
    }
    return client.ListUserPools()
}

func (a *CognitoProvider) GetPolicyInfo(info policyprovider.IntegrationInfo, applicationInfo policyprovider.ApplicationInfo) ([]hexapolicy.PolicyInfo, error) {
    client, err := awscognito.NewCognitoClient(info.Key, a.AwsClientOpts)
    if err != nil {
        return nil, err
    }

    groups, err := client.GetGroups(applicationInfo.ObjectID)
    if err != nil {
        return nil, err
    }

    var policies []hexapolicy.PolicyInfo
    for groupName := range groups {
        members, err := client.GetMembersAssignedTo(applicationInfo, groupName)
        if err != nil {
            return nil, err
        }
        policies = append(policies, hexapolicy.PolicyInfo{
            Meta: hexapolicy.MetaInfo{
                Version:      hexapolicy.IdqlVersion,
                ProviderType: ProviderTypeAwsCognito,
            },
            Actions:  []hexapolicy.ActionInfo{hexapolicy.ActionInfo(groupName)},
            Subjects: members,
            Object:   hexapolicy.ObjectInfo(applicationInfo.Name),
        })
    }

    return policies, nil
}

func (a *CognitoProvider) SetPolicyInfo(info policyprovider.IntegrationInfo, applicationInfo policyprovider.ApplicationInfo, policyInfos []hexapolicy.PolicyInfo) (int, error) {
    validate := validator.New() // todo - move this up?
    err := validate.Struct(applicationInfo)
    if err != nil {
        return http.StatusInternalServerError, err
    }
    err = validate.Var(policyInfos, "omitempty,dive")
    if err != nil {
        return http.StatusInternalServerError, err
    }

    client, err := awscognito.NewCognitoClient(info.Key, a.AwsClientOpts)
    if err != nil {
        return http.StatusInternalServerError, err
    }

    allGroups, err := client.GetGroups(applicationInfo.ObjectID)
    if err != nil {
        return http.StatusInternalServerError, err
    }
    for _, pol := range policyInfos {
        groupName := string(pol.Actions[0])
        _, exists := allGroups[groupName]
        if !exists {
            continue
        }

        err = client.SetGroupsAssignedTo(groupName, pol.Subjects, applicationInfo)
        if err != nil {
            return http.StatusInternalServerError, err
        }
    }

    return http.StatusCreated, nil
}
