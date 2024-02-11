package apim_testsupport

import (
	"github.com/hexa-org/policy-mapper/models/rar"
	"github.com/hexa-org/policy-mapper/models/rar/testsupport/policytestsupport"
	"github.com/hexa-org/policy-mapper/providers/azure/azarm/armmodel"
	"github.com/stretchr/testify/mock"
)

type MockApimNamedValueSvc struct {
	mock.Mock
}

func NewMockApimNamedValueSvc() *MockApimNamedValueSvc {
	return &MockApimNamedValueSvc{}
}

func (m *MockApimNamedValueSvc) GetResourceRoles(s armmodel.ApimServiceInfo) ([]rar.ResourceActionRoles, error) {
	returnArgs := m.Called(s)
	return returnArgs.Get(0).([]rar.ResourceActionRoles), returnArgs.Error(1)
}

func (m *MockApimNamedValueSvc) UpdateResourceRole(s armmodel.ApimServiceInfo, nv rar.ResourceActionRoles) error {
	returnArgs := m.Called(s, nv)
	return returnArgs.Error(0)
}

func (m *MockApimNamedValueSvc) ExpectGetResourceRoles(serviceInfo armmodel.ApimServiceInfo, retActionRoles map[string][]string) {
	expReturnResourceRoles := policytestsupport.MakeRarList(retActionRoles)
	m.On("GetResourceRoles", serviceInfo).
		Return(expReturnResourceRoles, nil)
}
