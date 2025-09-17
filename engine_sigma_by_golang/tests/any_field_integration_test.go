package tests

import (
	"testing"

	ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
	comp "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
	"github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
	"github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/matcher"
)

func TestScalarSelectionsMatchAnyField(t *testing.T) {
	rule := `
title: Touch Arguments
logsource:
  product: linux
  service: auditd
detection:
  execve:
    type: "EXECVE"
  touch:
    - "touch"
  selection2:
    - "-t"
    - "-d"
  condition: execve and touch and selection2
`

	c := comp.New()
	if _, err := c.CompileRule(rule); err != nil {
		t.Fatalf("CompileRule error: %v", err)
	}
	rs := c.IntoRuleset()

	builder := dag.NewDagBuilder().FromRuleset(rs)
	compiledDag, err := builder.Build()
	if err != nil {
		t.Fatalf("build dag: %v", err)
	}

	primMap := make(map[uint32]*matcher.CompiledPrimitive)
	for i := range rs.Primitives {
		cp, err := matcher.FromPrimitive(rs.Primitives[i])
		if err != nil {
			t.Fatalf("compile primitive %d: %v", i, err)
		}
		primMap[uint32(i)] = cp
	}

	evaluator := dag.WithPrimitives(compiledDag, primMap)

	matching := map[string]any{
		"type": "EXECVE",
		"a0":   "touch",
		"a1":   "-t",
	}

	res, err := evaluator.Evaluate(matching)
	if err != nil {
		t.Fatalf("evaluate matching: %v", err)
	}
	if len(res.MatchedRules) != 1 {
		t.Fatalf("expected 1 rule match, got %d", len(res.MatchedRules))
	}

	nonMatching := map[string]any{
		"type": "EXECVE",
		"a0":   "ls",
		"a1":   "-l",
	}

	res2, err := evaluator.Evaluate(nonMatching)
	if err != nil {
		t.Fatalf("evaluate non matching event: %v", err)
	}
	if len(res2.MatchedRules) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(res2.MatchedRules))
	}

	// Ensure primitives include any-field sentinel for scalar selections
	foundAny := false
	for _, p := range rs.Primitives {
		if p.Field == ir.AnyFieldSentinel {
			foundAny = true
			break
		}
	}
	if !foundAny {
		t.Fatalf("expected at least one any-field primitive in compiled ruleset")
	}
}
