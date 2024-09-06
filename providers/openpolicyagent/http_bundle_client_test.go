package openpolicyagent_test

import (
    "bytes"
    "errors"
    "fmt"

    "math/rand"
    "os"
    "path/filepath"
    "runtime"
    "testing"
    "time"

    "github.com/hexa-org/policy-mapper/models/rar/testsupport"
    "github.com/hexa-org/policy-mapper/providers/openpolicyagent"
    "github.com/hexa-org/policy-mapper/providers/openpolicyagent/compressionsupport"
    "github.com/stretchr/testify/assert"
)

const expectedBundleData = `{
  "comment": "Policy data for testing only!",
  "policies": [
    {
      "meta": {
        "version": "0.7"
      },
      "actions": [
        {
          "actionUri": "http:GET:/"
        }
      ],
      "subjects:": [
        "any",
        "anyauthenticated"
      ],
      "object": {
        "resource_id": "aResourceId"
      }
    },
    {
      "meta": {
        "version": "0.7"
      },
      "actions": [
        {
          "actionUri": "http:GET:/sales"
        },
        {
          "actionUri": "http:GET:/marketing"
        }
      ],
      "subjects:": [
        "anyauthenticated",
        "sales@hexaindustries.io",
        "marketing@hexaindustries.io"
      ],
      "object": {
        "resource_id": "aResourceId"
      }
    },
    {
      "meta": {
        "version": "0.7"
      },
      "actions": [
        {
          "actionUri": "http:GET:/accounting"
        },
        {
          "actionUri": "http:POST:/accounting"
        }
      ],
      "subjects:": [
        "accounting@hexaindustries.io"
      ],
      "object": {
        "resource_id": "aResourceId"
      }
    },
    {
      "meta": {
        "version": "0.7"
      },
      "actions": [
        {
          "actionUri": "http:GET:/humanresources"
        }
      ],
      "subjects:": [
        "humanresources@hexaindustries.io"
      ],
      "object": {
        "resource_id": "aResourceId"
      }
    }
  ]
}`

func TestHTTPBundleClient_GetExpressionFromBundle(t *testing.T) {
    _, file, _, _ := runtime.Caller(0)
    join := filepath.Join(file, "../resources/bundles")
    tar, _ := compressionsupport.TarFromPath(join)
    var buffer bytes.Buffer
    _ = compressionsupport.Gzip(&buffer, tar)
    random := rand.New(rand.NewSource(time.Now().UnixNano()))
    path := filepath.Join(t.TempDir(), fmt.Sprintf("test-bundles/.bundle-%d", random.Uint64()))

    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["http://someURL/bundles/bundle.tar.gz"] = buffer.Bytes()
    client := openpolicyagent.HTTPBundleClient{BundleServerURL: "http://someURL", HttpClient: m}

    data, err := client.GetDataFromBundle(path)

    assert.NoError(t, err)
    assert.Equal(t, expectedBundleData, string(data))
}

func TestHTTPBundleClient_GetExpressionFromBundleWithAuth(t *testing.T) {
    _, file, _, _ := runtime.Caller(0)
    join := filepath.Join(file, "../resources/bundles")
    tar, _ := compressionsupport.TarFromPath(join)
    var buffer bytes.Buffer
    _ = compressionsupport.Gzip(&buffer, tar)
    random := rand.New(rand.NewSource(time.Now().UnixNano()))
    path := filepath.Join(t.TempDir(), fmt.Sprintf("test-bundles/.bundle-%d", random.Uint64()))

    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["http://someURL/bundles/bundle.tar.gz"] = buffer.Bytes()
    token := "testToken"
    m.Auth = token
    client := openpolicyagent.HTTPBundleClient{BundleServerURL: "http://someURL", Authorization: &token, HttpClient: m}

    data, err := client.GetDataFromBundle(path)

    assert.NoError(t, err)
    assert.Equal(t, expectedBundleData, string(data))
}

func TestHTTPBundleClient_GetExpressionFromBundleWithBadAuth(t *testing.T) {
    _, file, _, _ := runtime.Caller(0)
    join := filepath.Join(file, "../resources/bundles")
    tar, _ := compressionsupport.TarFromPath(join)
    var buffer bytes.Buffer
    _ = compressionsupport.Gzip(&buffer, tar)
    random := rand.New(rand.NewSource(time.Now().UnixNano()))
    path := filepath.Join(t.TempDir(), fmt.Sprintf("test-bundles/.bundle-%d", random.Uint64()))

    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["http://someURL/bundles/bundle.tar.gz"] = buffer.Bytes()
    token := "testToken"
    m.Auth = "wrongToken"
    client := openpolicyagent.HTTPBundleClient{BundleServerURL: "http://someURL", Authorization: &token, HttpClient: m}

    data, err := client.GetDataFromBundle(path)

    assert.Error(t, err, "Should be a bad match")
    assert.Nil(t, data, "No response from OpenPolicyAgent.")
}

func TestHTTPBundleClient_GetExpressionFromBundle_withBadTar(t *testing.T) {
    _, file, _, _ := runtime.Caller(0)
    join := filepath.Join(file, "../resources/bundles")
    tar, _ := compressionsupport.TarFromPath(join)
    var buffer bytes.Buffer
    _ = compressionsupport.Gzip(&buffer, tar)

    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["http://someURL/bundles/bundle.tar.gz"] = buffer.Bytes()
    client := openpolicyagent.HTTPBundleClient{BundleServerURL: "http://someURL", HttpClient: m}

    _, err := client.GetDataFromBundle("/badPath")

    assert.Error(t, err, "unable to untar to path")
}

func TestHTTPBundleClient_GetExpressionFromBundle_withBadRequest(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["http://someURL/bundles/bundle.tar.gz"] = nil
    m.Err = errors.New("oops")
    client := openpolicyagent.HTTPBundleClient{BundleServerURL: "http://someURL", HttpClient: m}

    _, err := client.GetDataFromBundle(os.TempDir())

    assert.EqualError(t, err, "oops")
}

func TestHTTPBundleClient_GetExpressionFromBundle_withBadGzip(t *testing.T) {
    m := testsupport.NewMockHTTPClient()
    m.ResponseBody["http://someURL/bundles/bundle.tar.gz"] = []byte("bad gzip")
    client := openpolicyagent.HTTPBundleClient{BundleServerURL: "http://someURL", HttpClient: m}

    _, err := client.GetDataFromBundle("")

    assert.Error(t, err, "unable to ungzip")
}
