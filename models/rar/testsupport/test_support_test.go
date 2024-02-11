package testsupport_test

import (
	"testing"

	"github.com/hexa-org/policy-mapper/models/rar/testsupport"
	"github.com/stretchr/testify/assert"
)

type TestData struct {
	data string
}

func (t *TestData) SetUp() {
	t.data = "aTest"
}

func (t *TestData) TearDown() {
}

func TestWithSetUp(t *testing.T) {
	testsupport.WithSetUp(&TestData{}, func(d *TestData) {
		assert.Equal(t, "aTest", d.data)
	})
}
