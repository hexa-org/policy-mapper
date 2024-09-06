package awsapigwProvider

import (
    "net/http"

    "github.com/hexa-org/policy-mapper/api/policyprovider"
    "github.com/hexa-org/policy-mapper/models/rar"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
    "github.com/hexa-org/policy-mapper/providers/aws/awsapigwProvider/dynamodbpolicy"
    "github.com/hexa-org/policy-mapper/providers/aws/awscognito"

    log "golang.org/x/exp/slog"
)

type AwsApiGatewayProviderService struct {
    cognitoClient awscognito.CognitoClient
    policySvc     dynamodbpolicy.PolicyStoreSvc
}

func NewAwsApiGatewayProviderService(cognitoClient awscognito.CognitoClient, policySvc dynamodbpolicy.PolicyStoreSvc) *AwsApiGatewayProviderService {
    return &AwsApiGatewayProviderService{cognitoClient: cognitoClient, policySvc: policySvc}
}

func (s *AwsApiGatewayProviderService) DiscoverApplications(_ policyprovider.IntegrationInfo) ([]policyprovider.ApplicationInfo, error) {
    return s.cognitoClient.ListUserPools()
}

func (s *AwsApiGatewayProviderService) GetPolicyInfo(appInfo policyprovider.ApplicationInfo) ([]hexapolicy.PolicyInfo, error) {
    rarList, err := s.policySvc.GetResourceRoles()
    if err != nil {
        log.Error("AwsApiGatewayProviderService.GetPolicyInfo", "error calling GetResourceRoles App.Name", appInfo.Name, "identifierUrl[0]", appInfo.Service, "err=", err)
        return []hexapolicy.PolicyInfo{}, err
    }
    return rar.BuildPolicies(rarList), nil
}

func (s *AwsApiGatewayProviderService) SetPolicyInfo(appInfo policyprovider.ApplicationInfo, policyInfos []hexapolicy.PolicyInfo) (int, error) {
    rarList, err := s.policySvc.GetResourceRoles()
    if err != nil {
        log.Error("AwsApiGatewayProviderService.SetPolicyInfo", "error calling GetResourceRoles App.Name", appInfo.Name, "identifierUrl[0]", appInfo.Service, "err=", err)
        return http.StatusBadGateway, err
    }

    rarUpdateList := rar.CalcResourceActionRolesForUpdate(rarList, policyInfos)
    for _, rarItem := range rarUpdateList {
        err = s.policySvc.UpdateResourceRole(rarItem)
        if err != nil {
            return http.StatusBadGateway, err
        }
    }
    return http.StatusCreated, nil
}

func (s *AwsApiGatewayProviderService) setPolicyInfoOld(appInfo policyprovider.ApplicationInfo, policyInfos []hexapolicy.PolicyInfo) (int, error) {
    allGroups, err := s.cognitoClient.GetGroups(appInfo.ObjectID)
    if err != nil {
        return http.StatusInternalServerError, err
    }
    for _, pol := range policyInfos {
        groupName := string(pol.Actions[0])
        _, exists := allGroups[groupName]
        if !exists {
            continue
        }

        err = s.cognitoClient.SetGroupsAssignedTo(groupName, pol.Subjects, appInfo)
        if err != nil {
            return http.StatusInternalServerError, err
        }
    }

    return http.StatusCreated, nil
}
