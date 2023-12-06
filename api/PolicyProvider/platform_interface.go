/*
Package PolicyProvider defines the common structures and interfaces (the API) to be implemented by each platform that Hexa
integrates with.
*/
package PolicyProvider

import (
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"
)

/*
Provider defines the common interface Hexa uses to connect to platforms to access and update security Policy. Each
new Hexa Provider must implement this interface.
*/
type Provider interface {
    Name() string

    // DiscoverApplications returns the available platform workspaces/projects available based on IntegrationInfo
    DiscoverApplications(IntegrationInfo) ([]ApplicationInfo, error)

    // GetPolicyInfo retrieves all the available policies within an ApplicationInfo project
    GetPolicyInfo(IntegrationInfo, ApplicationInfo) ([]hexapolicy.PolicyInfo, error)

    // SetPolicyInfo updates the provided policies within the ApplicationInfo project
    SetPolicyInfo(IntegrationInfo, ApplicationInfo, []hexapolicy.PolicyInfo) (status int, foundErr error)
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
PolicyContext is an extension of ApplicationInfo and defines a Policy Application Point. In some systems this
may be the resource object identified within a policy or it may a common PAP.
*/
type PolicyContext struct {
    ApplicationInfo
    PapResource []hexapolicy.ObjectInfo // Identifies the deployment point for policy. In some cases this is also the Hexa Policy Object
}
