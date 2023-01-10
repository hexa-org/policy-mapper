package policysupport

import (
	"encoding/json"
	"os"
)

// ParsePolicyFile parses a file containing IDQL policy data in JSON form. The top level attribute is "policies" which
// is an array of IDQL Policies ([]PolicyInfo)
func ParsePolicyFile(path string) ([]PolicyInfo, error) {
	policyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePolicies(policyBytes)
}

// ParsePolicies parses an array of bytes representing an IDQL policy data in JSON form. The top level attribute is "policies" which
// is an array of IDQL Policies ([]PolicyInfo)
func ParsePolicies(policyBytes []byte) ([]PolicyInfo, error) {
	var policies Policies
	err := json.Unmarshal(policyBytes, &policies)
	if err != nil {
		return nil, err
	}
	return policies.Policies, nil
}

func ToBytes(policies []PolicyInfo) ([]byte, error) {
	pol := Policies{Policies: policies}
	return json.Marshal(&pol)
}

func WritePolicies(path string, policies []PolicyInfo) error {
	polBytes, err := ToBytes(policies)
	if err != nil {
		return err
	}
	return os.WriteFile(path, polBytes, 0644)
}
