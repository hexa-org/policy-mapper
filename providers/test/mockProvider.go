package test

import (
	"bytes"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/hexa-org/policy-mapper/api/PolicyProvider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
)

const (
	ProviderTypeMock string = "mock"
	TestPapId        string = "somewhereToMock"
)

type MockProvider struct {
	Policies []hexapolicy.PolicyInfo
	PapId    string
	Info     PolicyProvider.IntegrationInfo
}

func (p *MockProvider) Name() string {
	return ProviderTypeMock
}

func (p *MockProvider) checkInit() {
	if p.PapId == "" {
		p.PapId = TestPapId
	}
}
func (p *MockProvider) DiscoverApplications(info PolicyProvider.IntegrationInfo) ([]PolicyProvider.ApplicationInfo, error) {
	p.checkInit()
	app := PolicyProvider.ApplicationInfo{
		ObjectID:    p.PapId,
		Name:        ProviderTypeMock,
		Description: "Mock PAP",
		Service:     info.Name,
	}
	return []PolicyProvider.ApplicationInfo{app}, nil
}

func (p *MockProvider) GetPolicyInfo(info PolicyProvider.IntegrationInfo, pap PolicyProvider.ApplicationInfo) ([]hexapolicy.PolicyInfo, error) {
	p.checkInit()
	if info.Name != p.Info.Name || !bytes.Equal(p.Info.Key, info.Key) {
		return nil, errors.New("invalid integration")
	}
	if p.PapId != pap.ObjectID {
		return nil, errors.New("invalid PAP objectid")
	}
	return p.Policies, nil
}

func (p *MockProvider) SetPolicyInfo(info PolicyProvider.IntegrationInfo, pap PolicyProvider.ApplicationInfo, policies []hexapolicy.PolicyInfo) (status int, foundErr error) {
	p.checkInit()
	if info.Name != p.Info.Name || !bytes.Equal(p.Info.Key, info.Key) {
		return http.StatusBadRequest, errors.New("invalid integration")
	}
	if p.PapId != pap.ObjectID {
		return http.StatusBadRequest, errors.New("invalid PAP objectid")
	}
	// Check if meta information has been assigned
	for _, policy := range policies {
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
	}
	p.Policies = policies

	return http.StatusOK, nil
}

func (p *MockProvider) Reconcile(info PolicyProvider.IntegrationInfo, app PolicyProvider.ApplicationInfo, comparePolicies []hexapolicy.PolicyInfo, diffsOnly bool) ([]hexapolicy.PolicyDif, error) {
	p.checkInit()
	if info.Name != ProviderTypeMock || !bytes.Equal(p.Info.Key, info.Key) {
		return nil, errors.New("invalid integration")
	}
	if p.PapId != app.ObjectID {
		return nil, errors.New("invalid PAP objectid")
	}
	return hexapolicy.ReconcilePolicies(p.Policies, comparePolicies, diffsOnly)
}
