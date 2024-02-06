package iapProvider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/models/formats/gcpBind"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"google.golang.org/api/option"
	"google.golang.org/api/transport/http"

	"github.com/go-playground/validator/v10"
)

type GoogleProvider struct {
	HttpClientOverride HTTPClient
	GcpMapper          *gcpBind.GooglePolicyMapper
}

func (g *GoogleProvider) initMapper() {
	if g.GcpMapper == nil {
		g.GcpMapper = gcpBind.New(map[string]string{})
	}
}

func (g *GoogleProvider) Name() string {
	return "google_cloud"
}

func (g *GoogleProvider) Project(key []byte) string {
	return g.credentials(key).ProjectId
}

func (g *GoogleProvider) DiscoverApplications(info policyprovider.IntegrationInfo) (apps []policyprovider.ApplicationInfo, err error) {
	if !strings.EqualFold(info.Name, g.Name()) {
		return apps, err
	}

	key := info.Key
	foundCredentials := g.credentials(key)
	client, createClientErr := g.getHttpClient(key)
	if createClientErr != nil {
		fmt.Println("Unable to create google http client.")
		return apps, createClientErr
	}
	googleClient := GoogleClient{client, foundCredentials.ProjectId}

	backendApplications, err1 := googleClient.GetBackendApplications()
	apps = append(apps, backendApplications...)

	appEngineApplications, err2 := googleClient.GetAppEngineApplications()
	apps = append(apps, appEngineApplications...)

	err = err2
	// report first error
	if err1 != nil {
		err = err1
	}
	return apps, err
}

func (g *GoogleProvider) GetPolicyInfo(integration policyprovider.IntegrationInfo, app policyprovider.ApplicationInfo) (infos []hexapolicy.PolicyInfo, err error) {
	g.initMapper()

	key := integration.Key
	foundCredentials := g.credentials(key)
	client, createClientErr := g.getHttpClient(key)
	if createClientErr != nil {
		fmt.Println("Unable to create google http client.")
		return infos, createClientErr
	}
	googleClient := GoogleClient{client, foundCredentials.ProjectId}

	bindings, err := googleClient.GetBackendPolicy(app.Name, app.ObjectID)
	if err != nil {
		return infos, err
	}

	result := make([]hexapolicy.PolicyInfo, len(bindings))
	for i, binding := range bindings {
		result[i], err = g.GcpMapper.MapBindingToPolicy(app.ObjectID, binding)
		if err != nil {
			return infos, err
		}
	}
	return result, nil
}

func (g *GoogleProvider) SetPolicyInfo(integration policyprovider.IntegrationInfo, app policyprovider.ApplicationInfo, policyInfos []hexapolicy.PolicyInfo) (int, error) {
	g.initMapper()

	validate := validator.New() // todo - move this up?
	errApp := validate.Struct(app)
	if errApp != nil {
		return 500, errApp
	}
	errPolicies := validate.Var(policyInfos, "omitempty,dive")
	if errPolicies != nil {
		return 500, errPolicies
	}

	key := integration.Key
	foundCredentials := g.credentials(key)
	client, createClientErr := g.getHttpClient(key)
	if createClientErr != nil {
		fmt.Println("Unable to create google http client.")
		return 500, createClientErr
	}
	googleClient := GoogleClient{client, foundCredentials.ProjectId}
	for _, policyInfo := range policyInfos {

		binding, err := g.GcpMapper.MapPolicyToBinding(policyInfo)
		if err != nil {
			return 500, err
		}

		err = googleClient.SetBackendPolicy(app.Name, app.ObjectID, binding)
		if err != nil {
			return 500, err
		}
	}
	return 201, nil
}

func (g *GoogleProvider) NewHttpClient(key []byte) (HTTPClient, error) {
	var opts []option.ClientOption
	opt := option.WithCredentialsJSON(key)
	opts = append([]option.ClientOption{option.WithScopes("https://www.googleapis.com/auth/cloud-platform")}, opt)
	client, _, err := http.NewClient(context.Background(), opts...)
	return client, err
}

type credentials struct {
	ProjectId string `json:"project_id"`
}

func (g *GoogleProvider) credentials(key []byte) credentials {
	var foundCredentials credentials
	_ = json.NewDecoder(bytes.NewReader(key)).Decode(&foundCredentials)
	return foundCredentials
}

func (g *GoogleProvider) getHttpClient(key []byte) (HTTPClient, error) {
	if g.HttpClientOverride != nil {
		return g.HttpClientOverride, nil
	}
	return g.NewHttpClient(key)
}
