package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"path/filepath"
	policysupport "policy-mapper/policySupport"
	"runtime"
	"testing"
	"time"
)

func TestReadFile(t *testing.T) {
	idqlPath := getFile()

	policies, err := policysupport.ParsePolicyFile(idqlPath)
	assert.NoError(t, err, "File %s not parsed", idqlPath)

	assert.Equal(t, 4, len(policies), "Expecting 4 policies")
}

func TestWriteFile(t *testing.T) {
	policies, err := policysupport.ParsePolicyFile(getFile())
	assert.NoError(t, err, "File %s not parsed", getFile())

	rand.Seed(time.Now().UnixNano())
	dir := t.TempDir()

	tmpFile := filepath.Join(dir, fmt.Sprintf("idqldata-%d.json", rand.Uint64()))
	err = policysupport.WritePolicies(tmpFile, policies)
	assert.NoError(t, err, "Check error on writing policy")

	policyCopy, err := policysupport.ParsePolicyFile(tmpFile)
	assert.Equal(t, 4, len(policyCopy), "4 policies in copy parsed")
	assert.Equal(t, policies, policyCopy, "Check that the copy is the same as the original")
}

func getFile() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(file, "../resources/data.json")
}
