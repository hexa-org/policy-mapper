package main

import (
    "os"
    "path/filepath"
    "testing"

    "github.com/hexa-org/policy-mapper/hexaIdql/pkg/hexapolicysupport"
    "github.com/stretchr/testify/assert"
)

func TestIdqlAndCedar(t *testing.T) {
    // Map a simple file over to Cedar and then parse it back to Idql to test mapping in both directions
    testIdqlFilename := "examples/idqlAlice.json"

    target = "awsCedar"

    dir, _ := os.MkdirTemp(os.TempDir(), "hexaMapper-*")

    output = filepath.Join(dir, "aliceOut.txt")

    idqlToPlatform(testIdqlFilename)

    cedarFile := output

    output = filepath.Join(dir, "idqlAliceBack.json")

    platformToIdql(cedarFile)

    idqlResBytes, err := os.ReadFile(output)
    assert.NoError(t, err, "Error reading idql output file")
    origBytes, _ := os.ReadFile(testIdqlFilename)

    assert.Equal(t, len(idqlResBytes), len(origBytes), "Original and result are the same")

    os.Remove(cedarFile)
    os.Remove(output)
    os.Remove(dir)
}

func TestIdqlAndGcp(t *testing.T) {
    // Map a simple file over to GCP and then parse it back to Idql to test mapping in both directions
    // This also exercises the condition mapper
    testIdqlFilename := "examples/example_idql.json"

    target = "gcpBind"

    dir, _ := os.MkdirTemp(os.TempDir(), "hexaMapper-*")

    output = filepath.Join(dir, "gcpOut.json")

    idqlToPlatform(testIdqlFilename)

    gcpFile := output

    output = filepath.Join(dir, "idqlGcpBack.json")

    platformToIdql(gcpFile)

    policiesOrig, err := hexapolicysupport.ParsePolicyFile(testIdqlFilename)
    assert.NoError(t, err, "Error parsing original policy file")
    policiesRoundTrip, err := hexapolicysupport.ParsePolicyFile(output)
    assert.NoError(t, err, "Error parsing round trip policy file")

    assert.Equal(t, len(policiesOrig), len(policiesRoundTrip), "Original and result are the same")

    os.Remove(gcpFile)
    os.Remove(output)
    os.Remove(dir)
}
