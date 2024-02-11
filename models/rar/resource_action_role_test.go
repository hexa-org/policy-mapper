package rar_test

import (
	"net/http"
	"testing"

	rar "github.com/hexa-org/policy-mapper/models/rar"
	"github.com/stretchr/testify/assert"
)

const actionUri = "http:GET"

func TestNewResourceActionRoles_Invalid(t *testing.T) {
	act := rar.NewResourceActionRoles("/some", "INVALID", []string{})
	assert.Equal(t, rar.ResourceActionRoles{}, act)

	act = rar.NewResourceActionRoles("/some", "http:GET", []string{})
	assert.Equal(t, rar.ResourceActionRoles{}, act)

	act = rar.NewResourceActionRoles("/some", "httpget", []string{})
	assert.Equal(t, rar.ResourceActionRoles{}, act)

	act = rar.NewResourceActionRoles("  ", http.MethodGet, []string{})
	assert.Equal(t, rar.ResourceActionRoles{}, act)
}

func TestNewResourceActionRoles_Success(t *testing.T) {
	act := rar.NewResourceActionRoles("/some", http.MethodGet, []string{"mem1", "mem2"})
	assert.Equal(t, rar.ResourceActionRoles{
		Action:   http.MethodGet,
		Resource: "/some",
		Roles:    []string{"mem1", "mem2"},
	}, act)
}

func TestNewResourceActionUriRoles_InvalidMethod(t *testing.T) {
	act := rar.NewResourceActionUriRoles("/some", "INVALID", []string{})
	assert.Equal(t, rar.ResourceActionRoles{}, act)

	act = rar.NewResourceActionUriRoles("/some", http.MethodGet, []string{})
	assert.Equal(t, rar.ResourceActionRoles{}, act)

	act = rar.NewResourceActionUriRoles("/some", "httpget", []string{})
	assert.Equal(t, rar.ResourceActionRoles{}, act)
}

func TestNewResourceActionUriRoles_Success(t *testing.T) {
	act := rar.NewResourceActionUriRoles("/some", "http:GET", []string{"mem1", "mem2"})
	assert.Equal(t, rar.ResourceActionRoles{
		Action:   http.MethodGet,
		Resource: "/some",
		Roles:    []string{"mem1", "mem2"},
	}, act)
}

func TestNewResourceActionRolesFromProviderValue_Invalid(t *testing.T) {
	act := rar.NewResourceActionRolesFromProviderValue("invalid", []string{})
	assert.Equal(t, rar.ResourceActionRoles{}, act)

	act = rar.NewResourceActionRolesFromProviderValue("badprefix-httpget-some", []string{})
	assert.Equal(t, rar.ResourceActionRoles{}, act)

	act = rar.NewResourceActionRolesFromProviderValue("resrol-httpbadmethod-some", []string{})
	assert.Equal(t, rar.ResourceActionRoles{}, act)

	act = rar.NewResourceActionRolesFromProviderValue("resrol-httpget-some", []string{"mem1", "mem2"})
	assert.Equal(t, rar.ResourceActionRoles{
		Action:   http.MethodGet,
		Resource: "/some",
		Roles:    []string{"mem1", "mem2"},
	}, act)
}

func TestNewResourceActionRolesFromProviderValue(t *testing.T) {
	resActionKey := "resrol-httpget-humanresources-us"
	act := rar.NewResourceActionRolesFromProviderValue(resActionKey, []string{"some-role"})
	assert.Equal(t, http.MethodGet, act.Action)
	assert.Equal(t, "/humanresources/us", act.Resource)
	assert.Equal(t, []string{"some-role"}, act.Roles)
}

func TestMakeRarKeyForPolicy_Invalid(t *testing.T) {
	aKey := rar.MakeRarKeyForPolicy("  ", "/humanresources/us")
	assert.Equal(t, "", aKey)

	aKey = rar.MakeRarKeyForPolicy(actionUri, "  ")
	assert.Equal(t, "", aKey)

	aKey = rar.MakeRarKeyForPolicy(http.MethodGet, "/humanresources/us")
	assert.Equal(t, "", aKey)
}

func TestMakeRarKeyForPolicy(t *testing.T) {
	aKey := rar.MakeRarKeyForPolicy(actionUri, "/humanresources/us")
	assert.Equal(t, "resrol-httpget-humanresources-us", aKey)
}

func TestNameValue(t *testing.T) {
	resRole := rar.NewResourceActionUriRoles("/humanresources/us", actionUri, []string{"some-role"})
	assert.Equal(t, "resrol-httpget-humanresources-us", resRole.Name())
	assert.Equal(t, `["some-role"]`, resRole.Value())
}
