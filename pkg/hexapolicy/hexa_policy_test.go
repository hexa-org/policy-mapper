package hexapolicy_test

import (
	"encoding/json"
	"testing"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicy"
	"github.com/stretchr/testify/assert"
)

var testPolicy1 = `
{
      "meta": {
        "version": "0.5"
      },
      "actions": [
        {
          "action_uri": "http:GET:/accounting"
        },
        {
          "action_uri": "http:POST:/accounting"
        }
      ],
      "subject": {
        "members": [
          "accounting@hexaindustries.io"
        ]
      },
      "condition": {
        "rule": "req.ip sw 127 and req.method eq POST",
        "action": "allow"
      },
      "object": {
        "resource_id": "aResourceId"
      }
    }`

var testPolicy2 = `
{
      "meta": {
        "version": "0.5"
      },
      "actions": [
        {
          "action_uri": "http:GET:/humanresources"
        }
      ],
      "subject": {
        "members": [
          "humanresources@hexaindustries.io"
        ]
      },
      "object": {
        "resource_id": "aResourceId"
      }
    }`

func TestReadPolicy(t *testing.T) {
	var policy1, policy2, policy3 hexapolicy.PolicyInfo
	err := json.Unmarshal([]byte(testPolicy1), &policy1)
	assert.NoError(t, err, "Check no policy parse error #1")

	err = json.Unmarshal([]byte(testPolicy2), &policy2)
	assert.NoError(t, err, "Check no policy parse error #2")

	_ = json.Unmarshal([]byte(testPolicy1), &policy3)

	etag := policy1.Etag()
	assert.NoError(t, err, "Check no error with etag gen")
	assert.NotNil(t, etag, "Check that an etag was returned")
	assert.False(t, policy1.Equals(policy2), "Check policies not equal")
	assert.True(t, policy1.Equals(policy3), "Check that policy1 and policy3 are equal")

}
