package openpolicyagent_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/hexa-org/policy-mapper/api/policyprovider"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"

	"github.com/hexa-org/policy-mapper/providers/openpolicyagent"
	"github.com/hexa-org/policy-mapper/providers/openpolicyagent/compressionsupport"
	openpolicyagenttest "github.com/hexa-org/policy-mapper/providers/openpolicyagent/test"

	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDiscoverApplications(t *testing.T) {
	type expected struct {
		ObjectID string
		Service  string
	}

	tests := []struct {
		name     string
		key      []byte
		expected struct {
			ObjectID string
			Service  string
		}
	}{
		{
			name: "http bundle",
			key: []byte(`
              {
                "bundle_url": "aBigUrl"
              }`),
			expected: expected{ObjectID: base64.StdEncoding.EncodeToString([]byte("aBigUrl")),
				Service: fmt.Sprintf("Hexa OPA (%s)", openpolicyagent.BundleTypeHttp)},
		},
		{
			name: "gcp bundle storage project",
			key: []byte(`
{
  "gcp": {
    "bucket_name": "opa-bundles",
    "object_name": "bundle.tar.gz",
    "key": {
      "type": "service_account"
    }
  }
}
`),
			expected: expected{
				ObjectID: "opa-bundles",
				Service:  fmt.Sprintf("Hexa OPA (%s)", openpolicyagent.BundleTypeGcp),
			},
		},
		{
			name: "aws bundle storage project",
			key: []byte(`
{
  "aws": {
    "bucket_name": "opa-bundles",
    "object_name": "bundle.tar.gz",
	"key": {
      "region": "us-west-1"
    }
  }
}
`),
			expected: expected{
				ObjectID: "opa-bundles",
				Service:  fmt.Sprintf("Hexa OPA (%s)", openpolicyagent.BundleTypeAws),
			},
		},
		{
			name: "github bundle storage project",
			key: []byte(`
{
  "github": {
    "account": "hexa-org",
    "repo": "opa-bundles",
	"bundlePath": "bundle.tar.gz",
	"key": {
      "accessToken": "some_github_access_token"
    }
  }
}
`),
			expected: expected{
				ObjectID: "opa-bundles",
				Service:  fmt.Sprintf("Hexa OPA (%s)", openpolicyagent.BundleTypeGithub),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := openpolicyagent.OpaProvider{}

			applications, err := p.DiscoverApplications(policyprovider.IntegrationInfo{Name: openpolicyagent.ProviderTypeOpa, Key: tt.key})

			assert.NoError(t, err)
			assert.Equal(t, 1, len(applications))
			// assert.Equal(t, tt.expected.ProjectID, applications[0].Name)
			assert.Equal(t, tt.expected.ObjectID, applications[0].ObjectID)
			assert.Equal(t, "Open Policy Agent bundle", applications[0].Description)
			assert.Equal(t, tt.expected.Service, applications[0].Service)
		})
	}
}

func TestDiscoverApplications_Error(t *testing.T) {
	p := openpolicyagent.OpaProvider{}

	applications, err := p.DiscoverApplications(policyprovider.IntegrationInfo{Name: "open_policy_agent", Key: []byte("bad key")})

	assert.Empty(t, applications)
	assert.Error(t, err)
}

func TestOpaProvider_EnsureClientIsAvailable(t *testing.T) {
	tests := []struct {
		name           string
		key            []byte
		expectedClient any
	}{
		{
			name: "http bundle client",
			key: []byte(`
{
  "bundle_url": "aBigUrl"
}
`),
			expectedClient: &openpolicyagent.HTTPBundleClient{},
		},
		{
			name: "gcp bundle client",
			key: []byte(`
{
  "bundle_url": "aBigUrl",
  "gcp": {
    "bucket_name": "opa-bundles",
    "object_name": "bundle.tar.gz",
    "key": {
      "type": "service_account"
    }
  }
}
`),
			expectedClient: &openpolicyagent.GCPBundleClient{},
		},
		{
			name: "aws bundle client",
			key: []byte(`
{
  "aws": {
    "bucket_name": "opa-bundles",
    "object_name": "bundle.tar.gz",
	"key": {
      "region": "us-west-1"
    }
  }
}
`),
			expectedClient: &openpolicyagent.AWSBundleClient{},
		},
		{
			name: "github bundle client",
			key: []byte(`
{
  "project_id": "some github project",
  "github": {
    "account": "hexa-org",
    "repo": "opa-bundles",
	"bundlePath": "bundle.tar.gz",
	"key": {
      "accessToken": "some_github_access_token"
    }
  }
}
`),
			expectedClient: &openpolicyagent.GithubBundleClient{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, file, _, _ := runtime.Caller(0)

			resourcesDirectory := filepath.Join(file, "../resources")
			p := openpolicyagent.OpaProvider{ResourcesDirectory: resourcesDirectory}

			client, err := p.ConfigureClient(tt.key)

			assert.NoError(t, err)
			assert.NotNil(t, client)
			assert.IsType(t, tt.expectedClient, client)
		})
	}
}

func TestOpaProvider_EnsureClientIsAvailable_Error(t *testing.T) {
	key := []byte("bad key")
	p := openpolicyagent.OpaProvider{}

	_, err := p.ConfigureClient(key)

	assert.Contains(t, err.Error(), "invalid integration key")

	key = []byte(`
{
  "bundle_url": "bundleURL",
  "gcp": {"key": {"bad":"key"}},
  "aws": {"key": {"bad":"key"}},
  "github": {"key": {"bad":"key"}}
}
`)
	p = openpolicyagent.OpaProvider{}
	_, err = p.ConfigureClient(key)

	assert.Contains(t, err.Error(), "unable to create GCS storage client")
}

func TestGetPolicyInfo(t *testing.T) {
	key := []byte(`{"bundle_url": "aBigUrl"}`)
	_, file, _, _ := runtime.Caller(0)
	join := filepath.Join(file, "../resources/bundles/bundle/data.json")
	data, _ := os.ReadFile(join)
	m := &openpolicyagenttest.MockBundleClient{GetResponse: data}

	resourcesDirectory := filepath.Join(file, "../resources")
	p := openpolicyagent.OpaProvider{
		BundleClientOverride: m,
		ResourcesDirectory:   resourcesDirectory,
	}

	policies, _ := p.GetPolicyInfo(policyprovider.IntegrationInfo{Name: "open_policy_agent", Key: key}, policyprovider.ApplicationInfo{})

	assert.Equal(t, 4, len(policies))
}

func TestGetPolicyInfo_withBadKey(t *testing.T) {
	p := openpolicyagent.OpaProvider{
		BundleClientOverride: &openpolicyagenttest.MockBundleClient{},
	}

	_, err := p.GetPolicyInfo(
		policyprovider.IntegrationInfo{Name: "open_policy_agent", Key: []byte("bad key")},
		policyprovider.ApplicationInfo{},
	)

	assert.Contains(t, err.Error(), "invalid client")
}

func TestGetPolicyInfo_withBadRequest(t *testing.T) {
	key := []byte(`
{
  "bundle_url": "aBigUrl"
}
`)
	mockClient := &openpolicyagenttest.MockBundleClient{
		GetErr: errors.New("oops"),
	}
	p := openpolicyagent.OpaProvider{BundleClientOverride: mockClient}

	_, err := p.GetPolicyInfo(policyprovider.IntegrationInfo{Name: "open_policy_agent", Key: key}, policyprovider.ApplicationInfo{})

	assert.Error(t, err)
}

func TestSetPolicyInfo(t *testing.T) {
	key := []byte(`
{
  "bundle_url": "aBigUrl"
}
`)
	now := time.Now()
	mockClient := &openpolicyagenttest.MockBundleClient{PostStatusCode: http.StatusCreated}
	_, file, _, _ := runtime.Caller(0)
	p := openpolicyagent.OpaProvider{BundleClientOverride: mockClient, ResourcesDirectory: filepath.Join(file, "../resources")}

	status, err := p.SetPolicyInfo(
		policyprovider.IntegrationInfo{Name: "open_policy_agent", Key: key},
		policyprovider.ApplicationInfo{ObjectID: "anotherResourceId"},
		[]hexapolicy.PolicyInfo{
			{Meta: hexapolicy.MetaInfo{Version: hexapolicy.IdqlVersion}, Actions: []hexapolicy.ActionInfo{{"http:GET"}}, Subject: hexapolicy.SubjectInfo{Members: []string{"allusers"}}, Object: hexapolicy.ObjectInfo{
				ResourceID: "aResourceId",
			}},
		},
	)

	assert.Equal(t, http.StatusCreated, status)
	assert.NoError(t, err)

	gzip, _ := compressionsupport.UnGzip(bytes.NewReader(mockClient.ArgPostBundle))

	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	path := filepath.Join(file, fmt.Sprintf("../resources/bundles/.bundle-%d", random.Uint64()))
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			panic("Error cleaning up tests: " + err.Error())
		}
	}(path)
	_ = compressionsupport.UnTarToPath(bytes.NewReader(gzip), path)
	// readFile, _ := os.ReadFile(path + "/bundle/data.json")

	/*
		{"policies":[{"meta":{"version":"0.5","created":"2024-03-29T13:18:17.869827-07:00","modified":"2024-03-29T13:18:17.869827-07:00","policyId":"aResourceId_wRa","papId":"anotherResourceId","providerType":"opa"},"subject":{"members":["allusers"]},"actions":[{"actionUri":"http:GET"}],"object":{"resource_id":"aResourceId"}}]}
	*/
	policies, err := hexapolicysupport.ParsePolicyFile(path + "/bundle/data.json")
	assert.NoError(t, err, "Check policy parses")
	assert.Len(t, policies, 1, "Should be 1 policy")
	meta := policies[0].Meta
	modified := meta.Modified
	assert.True(t, now.Before(*modified))
	actionURi := policies[0].Actions[0].ActionUri
	assert.Equal(t, "http:GET", actionURi)
	assert.Equal(t, "aResourceId", policies[0].Object.ResourceID)
	// assert.JSONEq(t, `{"policies":[{"meta":{"version":"0.5"},"actions":[{"actionUri":"http:GET"}],"subject":{"members":["allusers"]},"object":{"resource_id":"anotherResourceId"}}]}`, string(readFile))
	assert.Equal(t, "anotherResourceId", *meta.PapId)
	assert.Equal(t, hexapolicy.IdqlVersion, meta.Version, "check version")
	assert.True(t, strings.Contains(*meta.PolicyId, "aResourceId_"), "Policy id was generated")
}

func TestSetPolicyInfo_withInvalidArguments(t *testing.T) {
	key := []byte(`
{
  "bundle_url": "aBigUrl"
}
`)
	client := &openpolicyagenttest.MockBundleClient{}
	_, file, _, _ := runtime.Caller(0)
	p := openpolicyagent.OpaProvider{BundleClientOverride: client, ResourcesDirectory: filepath.Join(file, "../resources")}

	status, err := p.SetPolicyInfo(
		policyprovider.IntegrationInfo{Name: "open_policy_agent", Key: key},
		policyprovider.ApplicationInfo{},
		[]hexapolicy.PolicyInfo{},
	)

	assert.Equal(t, 500, status)
	assert.Contains(t, err.Error(), "invalid app info")

	status, err = p.SetPolicyInfo(
		policyprovider.IntegrationInfo{Name: "open_policy_agent", Key: key},
		policyprovider.ApplicationInfo{ObjectID: "aResourceId"},
		[]hexapolicy.PolicyInfo{
			{
				Actions: []hexapolicy.ActionInfo{{"http:GET"}}, Subject: hexapolicy.SubjectInfo{Members: []string{"allusers"}}, Object: hexapolicy.ObjectInfo{
					ResourceID: "aResourceId",
				}},
		},
	)

	assert.Equal(t, 500, status)
	assert.Contains(t, err.Error(), "invalid policy info")

	key = []byte(`{
  "bundle_url": "aBigUrl",
  "gcp": {"key": {}}
}`)
	status, err = p.SetPolicyInfo(
		policyprovider.IntegrationInfo{Name: "open_policy_agent", Key: key},
		policyprovider.ApplicationInfo{ObjectID: "anObjectID"},
		[]hexapolicy.PolicyInfo{},
	)

	assert.Equal(t, 500, status)
	assert.Contains(t, err.Error(), "invalid client")
}

func TestSetPolicyInfo_WithHTTPSBundleServer(t *testing.T) {
	mockCalled := false
	bundleServer := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/bundles", r.URL.Path)
		mockCalled = true
		rw.WriteHeader(http.StatusCreated)
	}))
	caCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: bundleServer.Certificate().Raw,
	})

	integration := struct {
		BundleURL string `json:"bundle_url"`
		CACert    string `json:"ca_cert"`
	}{
		BundleURL: bundleServer.URL,
		CACert:    string(caCert),
	}
	key, err := json.Marshal(integration)
	assert.NoError(t, err)

	_, file, _, _ := runtime.Caller(0)
	p := openpolicyagent.OpaProvider{ResourcesDirectory: filepath.Join(file, "../resources")}
	status, err := p.SetPolicyInfo(
		policyprovider.IntegrationInfo{Name: "open_policy_agent", Key: key},
		policyprovider.ApplicationInfo{ObjectID: "aResourceId"},
		[]hexapolicy.PolicyInfo{
			{Meta: hexapolicy.MetaInfo{Version: "0.5"}, Actions: []hexapolicy.ActionInfo{{"http:GET"}}, Subject: hexapolicy.SubjectInfo{Members: []string{"allusers"}}, Object: hexapolicy.ObjectInfo{
				ResourceID: "aResourceId",
			}},
		},
	)
	assert.Equal(t, http.StatusCreated, status)
	assert.NoError(t, err)
	assert.True(t, mockCalled)
}

func TestMakeDefaultBundle(t *testing.T) {
	client := &openpolicyagent.HTTPBundleClient{}
	_, file, _, _ := runtime.Caller(0)
	p := openpolicyagent.OpaProvider{BundleClientOverride: client, ResourcesDirectory: filepath.Join(file, "../resources")}

	data := []byte(`{
  "policies": [
    {
      "meta": {
		"version": "0.6"
      },
      "actions": [{
        "actionUri": "ietf:http:GET"
	  }],
      "subject": {
        "members": [
          "anyauthenticated"
        ]
      },
      "object": {
        "resource_id": "aResourceId"
      }
    }
  ]
}`)
	bundle, _ := p.MakeDefaultBundle(data)

	gzip, _ := compressionsupport.UnGzip(bytes.NewReader(bundle.Bytes()))
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	path := filepath.Join(os.TempDir(), fmt.Sprintf("/test-bundle-%d", random.Uint64()))
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			if err != nil {
				panic("Error cleaning up tests: " + err.Error())
			}
		}
	}(path)
	_ = compressionsupport.UnTarToPath(bytes.NewReader(gzip), path)

	//created, _ := os.ReadFile(filepath.Join(path, "/bundle/policy.rego"))
	//assert.Contains(t, string(created), "package authz")

	policyv2, _ := os.ReadFile(filepath.Join(path, "/bundle/hexaPolicyV2.rego"))
	assert.Contains(t, string(policyv2), "package hexaPolicy")

	mcreated, _ := os.ReadFile(filepath.Join(path, "/bundle/.manifest"))
	assert.Contains(t, string(mcreated), "{\"revision\":\"\",\"roots\":[\"\"]}")

	policies, err := hexapolicysupport.ParsePolicyFile(filepath.Join(path, "/bundle/data.json"))
	assert.NoError(t, err, "Able to parse default policy bundle")

	assert.Len(t, policies, 1, "Should be 1 policy")
	meta := policies[0].Meta

	actionURi := policies[0].Actions[0].ActionUri
	assert.Equal(t, "ietf:http:GET", actionURi)
	assert.Equal(t, "aResourceId", policies[0].Object.ResourceID)
	// assert.JSONEq(t, `{"policies":[{"meta":{"version":"0.5"},"actions":[{"actionUri":"http:GET"}],"subject":{"members":["allusers"]},"object":{"resource_id":"anotherResourceId"}}]}`, string(readFile))
	// assert.Equal(t, "anotherResourceId", *meta.PapId)
	assert.Equal(t, "0.6", meta.Version, "check version")

	/*
	   	dcreated, _ := os.ReadFile(filepath.Join(path, "/bundle/data.json"))
	   	assert.Equal(t, `{
	     "policies": [
	       {
	         "version": "0.5",
	         "actionUri": "http:GET",
	         "subject": {
	           "members": [
	             "allusers",
	             "allauthenticated"
	           ]
	         },
	         "object": {
	           "resource_id": "aResourceId"
	         }
	       }
	     ]
	   }`, string(dcreated))

	*/

}
