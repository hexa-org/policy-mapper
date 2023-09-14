/*
Package PolicyProvider defines the common structures and interfaces (the API) to be implemented by each platform that Hexa
integrates with.
*/
package PolicyProvider

import (
	"github.com/hexa-org/policy-mapper/hexaIdql/pkg/hexapolicy"
)

/*
Provider defines the common interface Hexa uses to connect to platforms to access and update security Policy. Each
new Hexa Provider must implement this interface.
*/
type Provider interface {
	Name() string
	DiscoverPolicyContexts(IntegrationInfo) ([]PolicyContext, error)
	GetPolicyInfo(IntegrationInfo, PolicyContext) (*hexapolicy.Policies, error)
	SetPolicyInfo(IntegrationInfo, PolicyContext, hexapolicy.Policies) (status int, foundErr error)
}

/*
IntegrationInfo is a structure that provides the basic connectivity information to a platform.
*/
type IntegrationInfo struct {
	Name string // A unique Name identifying the platform integration.
	Key  []byte // Key is encoded JSON access data or token used to access a platform
}

/*
ApplicationInfo describes a unique cloud application environment context where one or more policy systems are found
*/
type ApplicationInfo struct {
	ObjectID    string `validate:"required"`
	Name        string // Name corresponds to IntegrationInfo.name
	Description string
	Service     string // Service describes an identifier for a service to be administered
}

/*
PolicyContext is an extension of ApplicationInfo and it is used where platforms administer policy directly to
a resource. For example, GCP can apply policy to an IAP Proxy Frontend, Backend, etc.
*/
type PolicyContext struct {
	ApplicationInfo
	Resource hexapolicy.ObjectInfo // Resource corresponds to an IDQL object resource where policy may be applied
}
