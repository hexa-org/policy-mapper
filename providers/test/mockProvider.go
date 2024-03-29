package test

import (
	"bytes"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
)

const (
	ProviderTypeMock string = "mock"
	PapIdTest        string = "somewhereToMock"
)

type MockProvider struct {
	Policies []hexapolicy.PolicyInfo
	PapId    string
	Info     policyprovider.IntegrationInfo
}

func (p *MockProvider) Name() string {
	return ProviderTypeMock
}

func (p *MockProvider) checkInit() {
	if p.PapId == "" {
		p.PapId = PapIdTest
	}
}
func (p *MockProvider) DiscoverApplications(info policyprovider.IntegrationInfo) ([]policyprovider.ApplicationInfo, error) {
	p.checkInit()
	app := policyprovider.ApplicationInfo{
		ObjectID:    p.PapId,
		Name:        ProviderTypeMock,
		Description: "Mock PAP",
		Service:     info.Name,
	}
	return []policyprovider.ApplicationInfo{app}, nil
}

func (p *MockProvider) GetPolicyInfo(info policyprovider.IntegrationInfo, pap policyprovider.ApplicationInfo) ([]hexapolicy.PolicyInfo, error) {
	p.checkInit()
	if info.Name != p.Info.Name || !bytes.Equal(p.Info.Key, info.Key) {
		return nil, errors.New("invalid integration")
	}
	if p.PapId != pap.ObjectID {
		return nil, errors.New("invalid PAP object id")
	}
	return p.Policies, nil
}

func (p *MockProvider) SetPolicyInfo(info policyprovider.IntegrationInfo, pap policyprovider.ApplicationInfo, policies []hexapolicy.PolicyInfo) (status int, foundErr error) {
	p.checkInit()
	if info.Name != p.Info.Name || !bytes.Equal(p.Info.Key, info.Key) {
		return http.StatusBadRequest, errors.New("invalid integration")
	}
	if p.PapId != pap.ObjectID {
		return http.StatusBadRequest, errors.New("invalid PAP object id")
	}
	// Check if meta information has been assigned
	for i, policy := range policies {
		meta := policy.Meta
		if meta.PapId == nil {
			meta.PapId = &p.PapId
		}
		if meta.PolicyId == nil {
			pid := uuid.New().String()
			meta.PolicyId = &pid
		}
		if meta.Created == nil {
			now := time.Now()
			meta.Created = &now
			meta.Modified = &now
		} else {
			now := time.Now()
			meta.Modified = &now
		}
		meta.ProviderType = ProviderTypeMock
		policy.Meta = meta
		policies[i] = policy
	}
	p.Policies = policies

	return http.StatusOK, nil
}

func (p *MockProvider) Reconcile(info policyprovider.IntegrationInfo, app policyprovider.ApplicationInfo, comparePolicies []hexapolicy.PolicyInfo, diffsOnly bool) ([]hexapolicy.PolicyDif, error) {
	p.checkInit()
	if info.Name != p.Info.Name || !bytes.Equal(p.Info.Key, info.Key) {
		return nil, errors.New("invalid integration")
	}
	if p.PapId != app.ObjectID {
		return nil, errors.New("invalid PAP object id")
	}

	existingPolicies := hexapolicy.Policies{Policies: p.Policies, App: &app.ObjectID}
	return existingPolicies.ReconcilePolicies(comparePolicies, diffsOnly), nil

}
