package matcher

import (
	"fmt"
	"strings"
	"testing"

	// TODO: đổi về import thật của bạn, nơi khai báo Primitive.
	engine "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

func strptr(s string) *string { return &s }

func TestCompilationPhaseEquality(t *testing.T) {
	if PrimitiveDiscovery != PrimitiveDiscovery {
		t.Fatalf("phase equality broken")
	}
	if PrimitiveDiscovery == PreCompilation {
		t.Fatalf("different phases should not be equal")
	}
}

func TestCompilationContextCreation(t *testing.T) {
	prim := engine.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil)
	lits := []string{"4624"}
	mods := []string{}

	ctx := NewCompilationContext(
		&prim,
		1,
		strptr("Test Rule"),
		lits,
		"EventID",
		"EventID",
		"equals",
		mods,
		true,
		0.1,
	)

	if ctx.RuleID != 1 {
		t.Fatalf("RuleID mismatch: %d", ctx.RuleID)
	}
	if ctx.RuleName == nil || *ctx.RuleName != "Test Rule" {
		t.Fatalf("RuleName mismatch: %#v", ctx.RuleName)
	}
	if ctx.LiteralValueCount() != 1 || ctx.LiteralValues[0] != "4624" {
		t.Fatalf("LiteralValues mismatch: %#v", ctx.LiteralValues)
	}
	if ctx.RawField != "EventID" || ctx.NormalizedField != "EventID" {
		t.Fatalf("field mismatch: %s/%s", ctx.RawField, ctx.NormalizedField)
	}
	if ctx.MatchType != "equals" {
		t.Fatalf("MatchType mismatch: %s", ctx.MatchType)
	}
	if !ctx.IsLiteralOnly {
		t.Fatalf("IsLiteralOnly expected true")
	}
	if ctx.SelectivityHint != 0.1 {
		t.Fatalf("SelectivityHint mismatch: %v", ctx.SelectivityHint)
	}
	if ctx.IsSummary() {
		t.Fatalf("should not be summary")
	}
	if ctx.HasModifiers() {
		t.Fatalf("expected no modifiers")
	}
}

func TestSummaryContext(t *testing.T) {
	ctx := NewSummaryContext(42, strptr("Summary Rule"))
	if ctx.RuleID != 42 {
		t.Fatalf("RuleID mismatch")
	}
	if ctx.RuleName == nil || *ctx.RuleName != "Summary Rule" {
		t.Fatalf("RuleName mismatch")
	}
	if !ctx.IsSummary() {
		t.Fatalf("expected summary context")
	}
	if ctx.LiteralValueCount() != 0 {
		t.Fatalf("expected 0 literal values")
	}
	if ctx.HasModifiers() {
		t.Fatalf("expected no modifiers")
	}
}

func TestContextDescription(t *testing.T) {
	prim := engine.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil)

	ctx := NewCompilationContext(
		&prim,
		1,
		strptr("Test Rule"),
		[]string{"4624"},
		"EventID",
		"EventID",
		"equals",
		nil,
		true,
		0.1,
	)

	desc := ctx.Description()
	for _, must := range []string{"EventID", "equals", "literal", "rule 1"} {
		if !strings.Contains(desc, must) {
			t.Fatalf("description missing %q: %s", must, desc)
		}
	}

	sum := NewSummaryContext(42, strptr("Summary Rule"))
	sumDesc := sum.Description()
	for _, must := range []string{"Summary context", "rule 42", "Summary Rule"} {
		if !strings.Contains(sumDesc, must) {
			t.Fatalf("summary description missing %q: %s", must, sumDesc)
		}
	}
}

func TestHookFunctionSignature(t *testing.T) {
	hook := CompilationHookFn(func(ctx *CompilationContext) error {
		if ctx.RuleID == 0 {
			return fmt.Errorf("invalid rule id")
		}
		return nil
	})

	ctx := NewSummaryContext(1, strptr("Test"))
	if err := hook(ctx); err != nil {
		t.Fatalf("hook error: %v", err)
	}
}

func TestHookFunctionError(t *testing.T) {
	hook := CompilationHookFn(func(_ *CompilationContext) error {
		return fmt.Errorf("Test hook error")
	})
	ctx := NewSummaryContext(1, strptr("Test"))
	err := hook(ctx)
	if err == nil || err.Error() != "Test hook error" {
		t.Fatalf("expected 'Test hook error', got %v", err)
	}
}
