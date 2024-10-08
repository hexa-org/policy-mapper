package iapProvider_test

import (
    "errors"
    "testing"

    "github.com/hexa-org/policy-mapper/models/formats/gcpBind"
    "github.com/hexa-org/policy-mapper/models/rar/testsupport"
    "github.com/hexa-org/policy-mapper/pkg/hexapolicy"

    "github.com/hexa-org/policy-mapper/providers/googlecloud/iapProvider"
    "github.com/stretchr/testify/assert"
)

func TestGoogleClient_GetAppEngineApplications(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["https://appengine.googleapis.com/v1/apps/projectID"] = appEngineAppsJSON
    client := iapProvider.GoogleClient{ProjectId: "projectID", HttpClient: m}

    applications, _ := client.GetAppEngineApplications()

    assert.Equal(t, 1, len(applications))
    assert.Equal(t, "hexa-demo", applications[0].ObjectID)
    assert.Equal(t, "apps/hexa-demo", applications[0].Name)
    assert.Equal(t, "hexa-demo.uc.r.appspot.com", applications[0].Description)
    assert.Equal(t, "AppEngine", applications[0].Service)
}

func TestGoogleClient_GetAppEngineApplications_when_404(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.StatusCode = 404
    client := iapProvider.GoogleClient{HttpClient: m}

    applications, _ := client.GetAppEngineApplications()

    assert.Equal(t, 0, len(applications))
}

func TestClient_GetAppEngineApplications_withRequestError(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.Err = errors.New("oops")

    client := iapProvider.GoogleClient{HttpClient: m}

    _, err := client.GetAppEngineApplications()
    assert.Error(t, err)
}

func TestClient_GetAppEngineApplications_withBadJson(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["compute"] = []byte("-")
    client := iapProvider.GoogleClient{HttpClient: m}

    _, err := client.GetAppEngineApplications()

    assert.Error(t, err)
}

func TestClient_GetBackendApplications(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["https://compute.googleapis.com/compute/v1/projects/projectID/global/backendServices"] = backendAppsJSON
    client := iapProvider.GoogleClient{ProjectId: "projectID", HttpClient: m}

    applications, _ := client.GetBackendApplications()

    assert.Equal(t, 3, len(applications))
    assert.Equal(t, "k8s1-aName", applications[0].Name)
    assert.Equal(t, "k8s1-anotherName", applications[1].Name)
    assert.Equal(t, "cloud-run-app", applications[2].Name)
    assert.Equal(t, "Kubernetes", applications[0].Service)
    assert.Equal(t, "Kubernetes", applications[1].Service)
    assert.Equal(t, "Cloud Run", applications[2].Service)
}

func TestClient_GetBackendApplications_withRequestError(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.Err = errors.New("oops")
    client := iapProvider.GoogleClient{HttpClient: m}

    _, err := client.GetBackendApplications()

    assert.Error(t, err)
}

func TestClient_GetBackendApplications_withBadJson(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["compute"] = []byte("-")
    client := iapProvider.GoogleClient{HttpClient: m}

    _, err := client.GetBackendApplications()

    assert.Error(t, err)
}

func TestGoogleClient_GetAppEnginePolicies(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["https://iap.googleapis.com/v1/projects/appengineproject/iap_web/appengine-appEngineObjectId/services/default:getIamPolicy"] = policyJSON
    client := iapProvider.GoogleClient{HttpClient: m, ProjectId: "appengineproject"}
    expectedUsers := []string{
        "user:phil@example.com",
        "group:admins@example.com",
        "domain:google.com",
        "serviceAccount:my-project-id@appspot.gserviceaccount.com",
    }

    infos, err := client.GetBackendPolicy("apps/EngineName", "appEngineObjectId")
    assert.NoError(t, err, "Check for Get App engine error")
    assert.Equal(t, 2, len(infos))
    assert.Equal(t, expectedUsers, infos[0].Members)
}

func TestGoogleClient_GetBackendPolicies(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["https://iap.googleapis.com/v1/projects/k8sproject/iap_web/compute/services/k8sObjectId:getIamPolicy"] = policyJSON
    client := iapProvider.GoogleClient{HttpClient: m, ProjectId: "k8sproject"}
    expectedUsers := []string{
        "user:phil@example.com",
        "group:admins@example.com",
        "domain:google.com",
        "serviceAccount:my-project-id@appspot.gserviceaccount.com",
    }

    infos, _ := client.GetBackendPolicy("k8sName", "k8sObjectId")

    assert.Equal(t, 2, len(infos))
    assert.Equal(t, expectedUsers, infos[0].Members)
}

func TestGoogleClient_GetBackendPolicies_withRequestError(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.Err = errors.New("oops")
    client := iapProvider.GoogleClient{HttpClient: m}

    _, err := client.GetBackendPolicy("k8sName", "anObjectId")

    assert.Error(t, err)
}

func TestGoogleClient_GetBackendPolicies_withBadJson(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["compute"] = []byte("-")
    client := iapProvider.GoogleClient{HttpClient: m}

    _, err := client.GetBackendPolicy("k8sName", "anObjectId")

    assert.Error(t, err)
}

func TestGoogleClient_SetAppEnginePolicies(t *testing.T) {
    policy := hexapolicy.PolicyInfo{
        Meta: hexapolicy.MetaInfo{Version: "aVersion"}, Actions: []hexapolicy.ActionInfo{"roles/iap.httpsResourceAccessor"}, Subjects: []string{"aUser"}, Object: "anObjectId",
    }

    mapper := gcpBind.New(map[string]string{})
    bindPolicy, err := mapper.MapPolicyToBinding(policy)
    assert.NoError(t, err)
    m := testsupport.NewMockHTTPClient()
    client := iapProvider.GoogleClient{HttpClient: m, ProjectId: "appengineproject"}

    err = client.SetBackendPolicy("apps/EngineName", "anObjectId", bindPolicy)

    assert.NoError(t, err)
    compare := string(m.GetRequestBody(m.Url))
    assert.JSONEq(t, `{
  "policy": {
    "bindings": [
      {
        "role": "roles/iap.httpsResourceAccessor",
        "members": [
          "aUser"
        ]
      }
    ]
  }
}`, compare)
    assert.Equal(t, "https://iap.googleapis.com/v1/projects/appengineproject/iap_web/appengine-anObjectId/services/default:setIamPolicy", m.Url)
}

func TestGoogleClient_SetBackendPolicies(t *testing.T) {
    policy := hexapolicy.PolicyInfo{
        Meta: hexapolicy.MetaInfo{Version: "aVersion"}, Actions: []hexapolicy.ActionInfo{"gcp:roles/iap.httpsResourceAccessor"}, Subjects: []string{"aUser"}, Object: "anObjectId",
    }
    mapper := gcpBind.New(map[string]string{})
    bindPolicy, err := mapper.MapPolicyToBinding(policy)
    m := testsupport.NewMockHTTPClient()
    client := iapProvider.GoogleClient{HttpClient: m, ProjectId: "k8sproject"}
    err = client.SetBackendPolicy("k8sName", "anObjectId", bindPolicy)
    assert.NoError(t, err)
    assert.JSONEq(t, `{
  "policy": {
    "bindings": [
      {
        "role": "roles/iap.httpsResourceAccessor",
        "members": [
          "aUser"
        ]
      }
    ]
  }
}`, string(m.GetRequestBody(m.Url)))
    assert.Equal(t, "https://iap.googleapis.com/v1/projects/k8sproject/iap_web/compute/services/anObjectId:setIamPolicy", m.Url)
}

func TestGoogleClient_SetBackendPolicies_withRequestError(t *testing.T) {
    policy := hexapolicy.PolicyInfo{
        Meta: hexapolicy.MetaInfo{Version: "aVersion"}, Actions: []hexapolicy.ActionInfo{"gcp:roles/iap.httpsResourceAccessor"}, Subjects: []string{"aUser"}, Object: "anObjectId",
    }
    mapper := gcpBind.New(map[string]string{})
    bindPolicy, err := mapper.MapPolicyToBinding(policy)
    m := testsupport.NewMockHTTPClient()
    m.Err = errors.New("oops")
    client := iapProvider.GoogleClient{HttpClient: m}
    err = client.SetBackendPolicy("k8sName", "anObjectId", bindPolicy)
    assert.Error(t, err)
}
