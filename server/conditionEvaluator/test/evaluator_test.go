package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
	"policy-conditions/server/conditionEvaluator"
	"testing"
)

var input = "{\"req\":{\"ip\":\"127.0.0.1:58810\",\"protocol\":\"HTTP/1.1\",\"method\":\"GET\",\"path\":\"/testpath\",\"param\":{\"a\":[\"b\"],\"c\":[\"d\"]},\"header\":{\"Accept-Encoding\":[\"gzip\"],\"Authorization\":[\"Basic dGVzdFVzZXI6Z29vZCZiYWQ=\"],\"User-Agent\":[\"Go-http-client/1.1\"]},\"time\":\"2022-12-02T11:17:27.91208-08:00\"},\"subject\":{\"type\":\"basic\",\"sub\":\"testUser\"}}"

func TestEvaluate(t *testing.T) {

	testVal := gjson.Get(input, "subject.sub")
	fmt.Println("subject=" + testVal.String())
	assert.Equal(t, "testUser", testVal.String())

	testVal = gjson.Get(input, "a.b")
	assert.Nil(t, testVal.Value())

	res, err := conditionEvaluator.Evaluate("req.ip sw \"127.0.0.1\"", input)
	assert.NoError(t, err, "Ensure evaluate has no error for SW")
	assert.Truef(t, res, "IP sw 127 is true")

	res, err = conditionEvaluator.Evaluate("req.ip sw \"192.0.0.1\"", input)
	assert.NoError(t, err, "Ensure evaluate has no error for SW")
	assert.Falsef(t, res, "IP sw 192 is false")

	res, err = conditionEvaluator.Evaluate("req.param.a eq \"b\"", input)
	assert.NoError(t, err, "Ensure evaluate has no error for EQ param")
	assert.Truef(t, res, "a = b is true")

	res, err = conditionEvaluator.Evaluate("req.param.c eq \"b\"", input)
	assert.NoError(t, err, "Ensure evaluate has no error for EQ param")
	assert.Falsef(t, res, "c = b is false")

	res, err = conditionEvaluator.Evaluate("req.param.c gt \"b\"", input)
	assert.NoError(t, err, "Ensure evaluate has no error for EQ param")
	assert.Truef(t, res, "c gt b is true")

	res, err = conditionEvaluator.Evaluate("subject.sub eq testUser and req.param.c gt \"b\"", input)
	assert.NoError(t, err, "Ensure evaluate has no error for and query")
	assert.Truef(t, res, "sub eq testUser and param.c gt b is true")

	res, err = conditionEvaluator.Evaluate("a.b eq testNoAttribute and req.param.c gt \"b\"", input)
	assert.NoError(t, err, "Ensure evaluate handles missing value")
	assert.False(t, res, "a.b eq testNoAttribute should be false")
}
