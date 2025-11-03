package ast

import (
	"errors"
	"sort"
	"strings"
)

// Position represents a location in the original policy document
// Lines and Columns are 1-based.
type Position struct {
	Line   int
	Column int
}

// Node is the interface implemented by all AST nodes.
// String returns the original JSON slice that corresponds to the node.
// Pos and End return the start and end position in the original document.
type Node interface {
	String() string
	Pos() Position
	End() Position
}

// baseNode provides common behavior for nodes.
type baseNode struct {
	text      string
	startByte int
	endByte   int // inclusive index
	// computed using line indexer
	start Position
	end   Position
}

func (b *baseNode) String() string { return b.text }
func (b *baseNode) Pos() Position  { return b.start }
func (b *baseNode) End() Position  { return b.end }

// DocumentNode is the root node that contains the policies array and all children policies.
type DocumentNode struct {
	baseNode
	Policies []*PolicyNode
}

// PolicyNode represents a single policy object with pointers to common fields when present.
type PolicyNode struct {
	baseNode
	Meta      *FieldNode
	Actions   *FieldNode
	Subjects  *FieldNode
	Object    *FieldNode
	Condition *FieldNode
}

// ConditionField returns the FieldNode for a given property inside the condition object
// (e.g., "rule" or "action"). Returns nil if condition is missing or not an object.
func (p *PolicyNode) ConditionField(name string) *FieldNode {
	if p == nil || p.Condition == nil || p.Condition.Value == nil || p.Condition.Value.Kind != "object" {
		return nil
	}
	for _, f := range p.Condition.Value.Fields {
		if strings.EqualFold(f.Name, name) {
			return f
		}
	}
	return nil
}

// ConditionRule returns the FieldNode for condition.rule if present.
func (p *PolicyNode) ConditionRule() *FieldNode { return p.ConditionField("rule") }

// ConditionAction returns the FieldNode for condition.action if present.
func (p *PolicyNode) ConditionAction() *FieldNode { return p.ConditionField("action") }

// FieldNode represents the span of a named field within a policy object, including the key and the value.
type FieldNode struct {
	baseNode
	Name  string
	Value *ValueNode
}

// ValueNode represents the span of a JSON value (object, array, string, number, boolean, or null).
type ValueNode struct {
	baseNode
	Kind     string       // object, array, string, number, boolean, null
	Elements []*ValueNode // for arrays: one node per element
	Fields   []*FieldNode // for objects: one field per property
}

// ParseAST parses the policyBytes JSON document and returns an AST with line/column positions.
// It accepts the same input variations as hexapolicysupport.ParsePolicies:
// - Top-level object with a "policies" array
// - Top-level array of policy objects
// - Single policy object
func ParseAST(policyBytes []byte) (*DocumentNode, error) {
	if len(policyBytes) == 0 {
		return nil, errors.New("empty policy document")
	}

	text := string(policyBytes)
	li := newLineIndex(policyBytes)

	// Whole document node
	doc := &DocumentNode{}
	doc.baseNode.text = strings.TrimRight(text, "\n\r\t ")
	doc.baseNode.startByte = 0
	doc.baseNode.endByte = len(doc.baseNode.text) - 1
	doc.baseNode.start = li.pos(0)
	doc.baseNode.end = li.pos(doc.baseNode.endByte)

	// Determine top-level token
	// find first non-space
	fs := 0
	for fs < len(text) && isSpace(text[fs]) {
		fs++
	}
	if fs >= len(text) {
		return doc, nil
	}

	switch text[fs] {
	case '{':
		// Either an envelope with policies array or a single policy object
		objEnd, ok := findMatching(text, fs)
		if !ok {
			return doc, errors.New("malformed top-level object")
		}
		// try to locate policies array within this object
		keyIdx := indexOfKeyInRange(text, "policies", fs, objEnd)
		if keyIdx >= 0 {
			// find '[' after the key within range
			brRel := strings.Index(text[keyIdx:objEnd+1], "[")
			if brRel < 0 {
				return doc, nil
			}
			arrStart := keyIdx + brRel
			arrEnd, ok := findMatching(text, arrStart)
			if !ok {
				return doc, errors.New("malformed policies array")
			}
			parsePoliciesArrayIntoDoc(doc, text, arrStart, arrEnd, li)
			return doc, nil
		}
		// single policy object
		pnode := buildPolicyNode(text, fs, objEnd, li)
		doc.Policies = append(doc.Policies, pnode)
		return doc, nil
	case '[':
		// top-level array of policy objects
		arrEnd, ok := findMatching(text, fs)
		if !ok {
			return doc, errors.New("malformed top-level array")
		}
		parsePoliciesArrayIntoDoc(doc, text, fs, arrEnd, li)
		return doc, nil
	default:
		// unsupported top-level; return empty doc
		return doc, nil
	}
}

func parsePoliciesArrayIntoDoc(doc *DocumentNode, text string, arrStart, arrEnd int, li *lineIndex) {
	// iterate over objects inside the array
	i := arrStart + 1
	for i < arrEnd {
		// skip whitespace and commas
		for i < arrEnd && isSpace(text[i]) {
			i++
		}
		if i < arrEnd && text[i] == ',' {
			i++
			continue
		}
		for i < arrEnd && isSpace(text[i]) {
			i++
		}
		if i >= arrEnd {
			break
		}
		if text[i] != '{' {
			// skip unexpected token
			nx := strings.IndexByte(text[i:arrEnd], ',')
			if nx < 0 {
				break
			}
			i += nx + 1
			continue
		}
		objStart := i
		objEnd, ok := findMatching(text, objStart)
		if !ok {
			break
		}
		pnode := buildPolicyNode(text, objStart, objEnd, li)
		doc.Policies = append(doc.Policies, pnode)
		i = objEnd + 1
	}
}

func buildPolicyNode(text string, start, end int, li *lineIndex) *PolicyNode {
	segment := text[start : end+1]
	pn := &PolicyNode{}
	pn.baseNode.text = strings.TrimSpace(segment)
	pn.baseNode.startByte = start
	pn.baseNode.endByte = end
	pn.baseNode.start = li.pos(start)
	pn.baseNode.end = li.pos(end)

	// known fields
	for _, field := range []string{"meta", "actions", "subjects", "object", "condition"} {
		fn := findField(text, field, start, end)
		if fn == nil {
			continue
		}
		fn.baseNode.start = li.pos(fn.baseNode.startByte)
		fn.baseNode.end = li.pos(fn.baseNode.endByte)
		fn.Value.baseNode.start = li.pos(fn.Value.baseNode.startByte)
		fn.Value.baseNode.end = li.pos(fn.Value.baseNode.endByte)
		// populate children for arrays/objects
		populateValueChildren(text, fn.Value, li)
		switch field {
		case "meta":
			pn.Meta = fn
		case "actions":
			pn.Actions = fn
		case "subjects":
			pn.Subjects = fn
		case "object":
			pn.Object = fn
		case "condition":
			pn.Condition = fn
		}
	}
	return pn
}

func findField(text, name string, objStart, objEnd int) *FieldNode {
	keyStart := indexOfKeyInRange(text, name, objStart, objEnd)
	if keyStart < 0 {
		return nil
	}
	colon := strings.Index(text[keyStart:objEnd+1], ":")
	if colon < 0 {
		return nil
	}
	valStart := keyStart + colon + 1
	// skip spaces
	for valStart <= objEnd && isSpace(text[valStart]) {
		valStart++
	}
	if valStart > objEnd {
		return nil
	}
	valEnd := findValueEnd(text, valStart)
	if valEnd < 0 || valEnd > objEnd {
		return nil
	}
	// field span includes the key name through value
	// Determine field textual slice boundaries: backtrack to beginning of key token '"'
	keyTokStart := strings.LastIndex(text[objStart:keyStart], "\"")
	if keyTokStart >= 0 {
		keyStart = objStart + keyTokStart
	}
	fieldText := strings.TrimSpace(text[keyStart : valEnd+1])
	v := &ValueNode{baseNode: baseNode{
		text:      strings.TrimSpace(text[valStart : valEnd+1]),
		startByte: valStart,
		endByte:   valEnd,
	}, Kind: classifyKind(text[valStart])}
	fn := &FieldNode{
		baseNode: baseNode{
			text:      fieldText,
			startByte: keyStart,
			endByte:   valEnd,
		},
		Name:  name,
		Value: v,
	}
	return fn
}

func indexOfKey(text, name string) int {
	needle := "\"" + name + "\""
	idx := strings.Index(text, needle)
	return idx
}

func indexOfKeyInRange(text, name string, start, end int) int {
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	needle := "\"" + name + "\""
	idx := strings.Index(text[start:end], needle)
	if idx < 0 {
		return -1
	}
	return start + idx
}

func classifyKind(b byte) string {
	switch b {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

func isSpace(b byte) bool {
	switch b {
	case ' ', '\n', '\r', '\t':
		return true
	default:
		return false
	}
}

// findMatching finds the matching closing delimiter for '{' or '[' at start index.
// Returns the end index and true if found.
func findMatching(text string, start int) (int, bool) {
	if start < 0 || start >= len(text) {
		return -1, false
	}
	open := text[start]
	var close byte
	if open == '{' {
		close = '}'
	} else if open == '[' {
		close = ']'
	} else {
		return -1, false
	}
	depth := 0
	inString := false
	for i := start; i < len(text); i++ {
		c := text[i]
		if inString {
			if c == '\\' {
				i++ // skip escaped char
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		if c == open {
			depth++
			continue
		}
		if c == close {
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return -1, false
}

// findValueEnd returns the end index (inclusive) for a JSON value starting at start
func findValueEnd(text string, start int) int {
	if start >= len(text) {
		return -1
	}
	switch text[start] {
	case '{', '[':
		end, ok := findMatching(text, start)
		if !ok {
			return -1
		}
		return end
	case '"':
		// string
		i := start + 1
		for i < len(text) {
			c := text[i]
			if c == '\\' {
				i += 2
				continue
			}
			if c == '"' {
				return i
			}
			i++
		}
		return -1
	default:
		// number, boolean, or null: read until comma or end of object/array
		i := start
		for i < len(text) {
			c := text[i]
			if c == ',' || c == '}' || c == ']' || c == '\n' || c == '\r' {
				return i - 1
			}
			i++
		}
		return len(text) - 1
	}
}

// populateValueChildren fills Elements (arrays) and Fields (objects)
func populateValueChildren(text string, v *ValueNode, li *lineIndex) {
	switch v.Kind {
	case "array":
		start := v.startByte
		end := v.endByte
		i := start + 1 // after '['
		for i <= end-1 {
			// skip spaces and commas
			for i <= end-1 && isSpace(text[i]) {
				i++
			}
			if i <= end-1 && text[i] == ',' {
				i++
				continue
			}
			for i <= end-1 && isSpace(text[i]) {
				i++
			}
			if i > end-1 || text[i] == ']' {
				break
			}
			elemStart := i
			elemEnd := findValueEnd(text, elemStart)
			if elemEnd < 0 || elemEnd > end-1 {
				break
			}
			elem := &ValueNode{baseNode: baseNode{
				text:      strings.TrimSpace(text[elemStart : elemEnd+1]),
				startByte: elemStart,
				endByte:   elemEnd,
			}, Kind: classifyKind(text[elemStart])}
			elem.start = li.pos(elemStart)
			elem.end = li.pos(elemEnd)
			populateValueChildren(text, elem, li)
			v.Elements = append(v.Elements, elem)
			i = elemEnd + 1
		}
	case "object":
		start := v.startByte
		end := v.endByte
		i := start + 1 // after '{'
		for i <= end-1 {
			// skip whitespace and commas
			for i <= end-1 && isSpace(text[i]) {
				i++
			}
			if i <= end-1 && text[i] == ',' {
				i++
				continue
			}
			for i <= end-1 && isSpace(text[i]) {
				i++
			}
			if i > end-1 || text[i] == '}' {
				break
			}
			// parse key string
			if text[i] != '"' {
				// malformed, skip until next comma or end
				nx := i
				for nx <= end-1 && text[nx] != ',' && text[nx] != '}' {
					nx++
				}
				i = nx
				continue
			}
			keyStart := i
			// find end quote considering escapes
			j := keyStart + 1
			for j <= end-1 {
				c := text[j]
				if c == '\\' {
					j += 2
					continue
				}
				if c == '"' {
					break
				}
				j++
			}
			if j > end-1 || text[j] != '"' {
				break
			}
			keyEnd := j
			keyName := text[keyStart+1 : keyEnd]
			// find colon
			j++
			for j <= end-1 && isSpace(text[j]) {
				j++
			}
			if j > end-1 || text[j] != ':' {
				break
			}
			j++ // after ':'
			for j <= end-1 && isSpace(text[j]) {
				j++
			}
			if j > end-1 {
				break
			}
			valStart := j
			valEnd := findValueEnd(text, valStart)
			if valEnd < 0 || valEnd > end-1 {
				break
			}
			fv := &ValueNode{baseNode: baseNode{
				text:      strings.TrimSpace(text[valStart : valEnd+1]),
				startByte: valStart,
				endByte:   valEnd,
			}, Kind: classifyKind(text[valStart])}
			fv.start = li.pos(valStart)
			fv.end = li.pos(valEnd)
			populateValueChildren(text, fv, li)
			fieldStartByte := keyStart
			fieldEndByte := valEnd
			fn := &FieldNode{baseNode: baseNode{
				text:      strings.TrimSpace(text[fieldStartByte : fieldEndByte+1]),
				startByte: fieldStartByte,
				endByte:   fieldEndByte,
			}, Name: keyName, Value: fv}
			fn.start = li.pos(fieldStartByte)
			fn.end = li.pos(fieldEndByte)
			v.Fields = append(v.Fields, fn)
			i = valEnd + 1
		}
	}
}

// lineIndex maps byte offsets to line/column positions.
type lineIndex struct {
	starts []int // starting byte index of each line (0-based)
}

func newLineIndex(b []byte) *lineIndex {
	starts := []int{0}
	for i, c := range b {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &lineIndex{starts: starts}
}

func (li *lineIndex) pos(offset int) Position {
	if offset < 0 {
		offset = 0
	}
	if len(li.starts) == 0 {
		return Position{Line: 1, Column: offset + 1}
	}
	// find rightmost line start <= offset
	i := sort.Search(len(li.starts), func(i int) bool { return li.starts[i] > offset })
	line := i // first start greater than offset; our line index is i-1, but line numbers are 1-based
	if line == 0 {
		return Position{Line: 1, Column: offset + 1}
	}
	line--
	col := offset - li.starts[line] + 1
	return Position{Line: line + 1, Column: col}
}
