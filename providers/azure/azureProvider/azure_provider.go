package azureProvider

import (
    "errors"
    "log"
    "net/http"
    "strings"

    "github.com/go-playground/validator/v10"
    "github.com/hexa-org/policy-mapper/api/policyprovider"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
    "github.com/hexa-org/policy-mapper/pkg/workflowsupport"
    "github.com/hexa-org/policy-mapper/providers/azure/azad"
)

const ProviderTypeAzure string = "azure"

type AzureProvider struct {
    client azad.AzureClient
}

type ProviderOpt func(provider *AzureProvider)

func WithAzureClient(clientOverride azad.AzureClient) func(provider *AzureProvider) {
    return func(provider *AzureProvider) {
        provider.client = clientOverride
    }
}

func NewAzureProvider(opts ...ProviderOpt) *AzureProvider {
    provider := &AzureProvider{client: azad.NewAzureClient(&http.Client{})}
    if opts != nil {
        for _, opt := range opts {
            if opt != nil {
                opt(provider)
            }
        }
    }
    return provider
}

func (a *AzureProvider) Name() string {
    return ProviderTypeAzure
}

func (a *AzureProvider) DiscoverApplications(info policyprovider.IntegrationInfo) (apps []policyprovider.ApplicationInfo, err error) {
    if !strings.EqualFold(info.Name, a.Name()) {
        return apps, err
    }

    key := info.Key
    found, _ := a.client.GetWebApplications(key)
    apps = append(apps, found...)
    return apps, err
}

func (a *AzureProvider) GetPolicyInfo(integrationInfo policyprovider.IntegrationInfo, applicationInfo policyprovider.ApplicationInfo) ([]hexapolicy.PolicyInfo, error) {
    key := integrationInfo.Key
    servicePrincipals, _ := a.client.GetServicePrincipals(key, applicationInfo.Description) // todo - description is named poorly
    if len(servicePrincipals.List) == 0 {
        return []hexapolicy.PolicyInfo{}, nil
    }
    assignments, _ := a.client.GetAppRoleAssignedTo(key, servicePrincipals.List[0].ID)

    userEmailList := workflowsupport.ProcessAsync[azad.AzureUser, azad.AzureAppRoleAssignment](assignments.List, func(ara azad.AzureAppRoleAssignment) (azad.AzureUser, error) {
        user, _ := a.client.GetUserInfoFromPrincipalId(key, ara.PrincipalId)

        if user.Email == "" {
            return azad.AzureUser{}, errors.New("no email found for principalId " + ara.PrincipalId)
        }
        return azad.AzureUser{PrincipalId: ara.PrincipalId, Email: user.Email}, nil
    })

    userEmailMap := make(map[string]string)
    for _, ue := range userEmailList {
        if ue.PrincipalId != "" && ue.Email != "" {
            userEmailMap[ue.PrincipalId] = ue.Email
        }
    }

    policyMapper := NewAzurePolicyMapper(servicePrincipals, assignments.List, userEmailMap)
    return policyMapper.ToIDQL(), nil
}

func (a *AzureProvider) SetPolicyInfo(integrationInfo policyprovider.IntegrationInfo, applicationInfo policyprovider.ApplicationInfo, policyInfos []hexapolicy.PolicyInfo) (int, error) {
    validate := validator.New() // todo - move this up?
    errApp := validate.Struct(applicationInfo)
    if errApp != nil {
        return http.StatusInternalServerError, errApp
    }
    errPolicies := validate.Var(policyInfos, "omitempty,dive")
    if errPolicies != nil {
        return http.StatusInternalServerError, errPolicies
    }

    key := integrationInfo.Key

    sps, _ := a.client.GetServicePrincipals(key, applicationInfo.Description) // todo - description is named poorly

    appRoleValueToId := make(map[string]string)
    for _, ara := range sps.List[0].AppRoles {
        appRoleValueToId[ara.Value] = ara.ID
    }

    for _, policyInfo := range policyInfos {
        var assignments []azad.AzureAppRoleAssignment

        actionUri := strings.TrimPrefix(string(policyInfo.Actions[0]), "azure:")
        appRoleId, found := appRoleValueToId[actionUri]
        if !found {
            log.Println("No Azure AppRoleAssignment found for policy action", actionUri)
            continue
        }

        if len(policyInfo.Subjects) == 0 {
            assignments = append(assignments, azad.AzureAppRoleAssignment{
                AppRoleId:  appRoleId,
                ResourceId: sps.List[0].ID,
            })
        }

        for _, user := range policyInfo.Subjects {
            principalId, _ := a.client.GetPrincipalIdFromEmail(key, strings.Split(user, ":")[1])
            if principalId == "" {
                continue
            }
            assignments = append(assignments, azad.AzureAppRoleAssignment{
                AppRoleId:   appRoleId,
                PrincipalId: principalId,
                ResourceId:  sps.List[0].ID,
                // ResourceId:  strings.Split(policyInfo.Object.ResourceID, ":")[0],
            })
        }

        if len(assignments) == 0 {
            continue
        }

        err := a.client.SetAppRoleAssignedTo(key, sps.List[0].ID, assignments)
        if err != nil {
            return http.StatusInternalServerError, err
        }
    }
    return http.StatusCreated, nil
}
