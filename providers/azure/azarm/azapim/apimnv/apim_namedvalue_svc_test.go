package apimnv_test

import (
	"testing"

	"github.com/hexa-org/policy-mapper/models/rar"
	"github.com/hexa-org/policy-mapper/providers/azure/azarm/armmodel"
	"github.com/hexa-org/policy-mapper/providers/azure/azarm/azapim/apimnv"
	"github.com/stretchr/testify/assert"
)

func TestGetResourceRoles_NoServiceInfo(t *testing.T) {
	svc := apimnv.NewApimNamedValueSvc("", nil, nil)
	roles, err := svc.GetResourceRoles(armmodel.ApimServiceInfo{})
	assert.NoError(t, err)
	assert.NotNil(t, roles)
	assert.Equal(t, []rar.ResourceActionRoles{}, roles)
}
