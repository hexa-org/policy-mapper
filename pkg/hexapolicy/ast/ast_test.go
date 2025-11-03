package ast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAST_DocumentPoliciesCount(t *testing.T) {
	path := filepath.Join("..", "..", "hexapolicysupport", "test", "data.json")
	b, err := os.ReadFile(path)
	require.NoError(t, err)

	doc, err := ParseAST(b)
	require.NoError(t, err)
	require.NotNil(t, doc)

	assert.GreaterOrEqual(t, len(doc.Policies), 4, "expected at least 4 policies from sample data")

	// root positions
	start := doc.Pos()
	end := doc.End()
	assert.True(t, start.Line >= 1)
	assert.True(t, start.Column >= 1)
	assert.True(t, end.Line >= start.Line)
}

func TestParseAST_FieldKindsAndContent(t *testing.T) {
	path := filepath.Join("..", "..", "hexapolicysupport", "test", "data.json")
	b, err := os.ReadFile(path)
	require.NoError(t, err)

	doc, err := ParseAST(b)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.True(t, len(doc.Policies) >= 1)
	p := doc.Policies[0]

	if p.Meta != nil {
		assert.Equal(t, "meta", p.Meta.Name)
		assert.Equal(t, "object", p.Meta.Value.Kind)
		assert.Contains(t, p.Meta.Value.String(), "\"version\"")
		// Ensure object fields parsed
		require.GreaterOrEqual(t, len(p.Meta.Value.Fields), 1)
		foundVersion := false
		for _, f := range p.Meta.Value.Fields {
			if strings.EqualFold(f.Name, "version") {
				foundVersion = true
				assert.Equal(t, "string", f.Value.Kind)
				break
			}
		}
		assert.True(t, foundVersion, "meta.version field expected")
	}
	if p.Actions != nil {
		assert.Equal(t, "array", p.Actions.Value.Kind)
		assert.Contains(t, p.Actions.Value.String(), "http:")
		// Ensure array elements parsed
		require.GreaterOrEqual(t, len(p.Actions.Value.Elements), 1)
		for _, el := range p.Actions.Value.Elements {
			assert.Equal(t, "string", el.Kind)
		}
	}
	if p.Subjects != nil {
		assert.Equal(t, "array", p.Subjects.Value.Kind)
		require.GreaterOrEqual(t, len(p.Subjects.Value.Elements), 1)
		for _, el := range p.Subjects.Value.Elements {
			assert.Equal(t, "string", el.Kind)
		}
	}
	if p.Object != nil {
		assert.Equal(t, "string", p.Object.Value.Kind)
	}
	if p.Condition != nil {
		assert.Equal(t, "object", p.Condition.Value.Kind)
		assert.Contains(t, p.Condition.Value.String(), "rule")
		// Ensure condition has rule/action fields
		names := make([]string, 0, len(p.Condition.Value.Fields))
		for _, f := range p.Condition.Value.Fields {
			names = append(names, strings.ToLower(f.Name))
		}
		assert.Contains(t, names, "rule")
		assert.Contains(t, names, "action")
	}

	// Check field positions are within policy bounds
	if p.Actions != nil {
		ps := p.Pos()
		pe := p.End()
		fs := p.Actions.Pos()
		fe := p.Actions.End()
		assert.True(t, fs.Line >= ps.Line)
		assert.True(t, fe.Line <= pe.Line)
	}
}

func TestParseAST_AcceptsArrayRoot(t *testing.T) {
	json := `[
	  {
	    "meta": {"version": "0.7"},
	    "actions": ["http:GET:/"],
	    "subjects": ["any"],
	    "object": "res1"
	  },
	  {
	    "actions": ["http:POST:/a"],
	    "subjects": ["user:alice"],
	    "object": "res2"
	  }
	]`
	doc, err := ParseAST([]byte(json))
	require.NoError(t, err)
	require.NotNil(t, doc)
	assert.Equal(t, 2, len(doc.Policies))
	assert.NotNil(t, doc.Policies[0].Actions)
	assert.Equal(t, "array", doc.Policies[0].Actions.Value.Kind)
}

func TestParseAST_AcceptsSinglePolicyRoot(t *testing.T) {
	json := `{
	  "meta": {"version": "0.7"},
	  "actions": ["http:GET:/"],
	  "subjects": ["any"],
	  "object": "res1",
	  "condition": {"rule": "x eq y", "action": "allow"}
	}`
	doc, err := ParseAST([]byte(json))
	require.NoError(t, err)
	require.NotNil(t, doc)
	assert.Equal(t, 1, len(doc.Policies))
	p := doc.Policies[0]
	assert.NotNil(t, p.Condition)
	assert.Equal(t, "object", p.Condition.Value.Kind)
}
