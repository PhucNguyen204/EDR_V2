package matcher

import (
    "sync"
    "testing"

    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

func TestMatchRegistration(t *testing.T) {
    b := NewMatcherBuilder()
    initial := b.MatchTypeCount()

    b.RegisterMatch("custom", func(_ string, _ []string, _ []string) (bool, error) { return true, nil })

    if b.MatchTypeCount() != initial+1 {
        t.Fatalf("match type count = %d, want %d", b.MatchTypeCount(), initial+1)
    }
    if !b.HasMatchType("custom") {
        t.Fatalf("expected HasMatchType(custom) true")
    }
    if b.HasMatchType("nonexistent") {
        t.Fatalf("expected HasMatchType(nonexistent) false")
    }
}

func TestModifierRegistration(t *testing.T) {
    b := NewMatcherBuilder()
    initial := b.ModifierCount()

    b.RegisterModifier("uppercase", func(s string) (string, error) { return s, nil })

    if b.ModifierCount() != initial+1 {
        t.Fatalf("modifier count = %d, want %d", b.ModifierCount(), initial+1)
    }
    if !b.HasModifier("uppercase") {
        t.Fatalf("expected HasModifier(uppercase) true")
    }
    if b.HasModifier("nonexistent") {
        t.Fatalf("expected HasModifier(nonexistent) false")
    }
}

func TestPrimitiveCompilation(t *testing.T) {
    b := NewMatcherBuilder()
    prim := ir.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil)

    cp, err := b.compileOne(&prim)
    if err != nil {
        t.Fatalf("compileOne error: %v", err)
    }
    if cp.FieldPathString() != "EventID" {
        t.Fatalf("field path = %s, want EventID", cp.FieldPathString())
    }
    if cp.ValueCount() != 1 {
        t.Fatalf("value count = %d, want 1", cp.ValueCount())
    }
}

func TestUnsupportedMatchType(t *testing.T) {
    b := NewMatcherBuilder()
    prim := ir.NewPrimitiveStatic("EventID", "unsupported", []string{"4624"}, nil)

    _, err := b.compileOne(&prim)
    if err == nil {
        t.Fatalf("expected error for unsupported match type")
    }
    if _, ok := err.(*UnsupportedMatchTypeError); !ok {
        t.Fatalf("expected UnsupportedMatchTypeError, got %T", err)
    }
}

func TestNestedFieldCompilation(t *testing.T) {
    b := NewMatcherBuilder()
    prim := ir.NewPrimitiveStatic("nested.field", "equals", []string{"value"}, nil)

    cp, err := b.compileOne(&prim)
    if err != nil {
        t.Fatalf("compileOne error: %v", err)
    }
    if cp.FieldPathString() != "nested.field" {
        t.Fatalf("FieldPathString = %s", cp.FieldPathString())
    }
    if len(cp.fieldPath) != 2 { // same package -> access
        t.Fatalf("fieldPath len = %d, want 2", len(cp.fieldPath))
    }
}

func TestHookRegistration(t *testing.T) {
    b := NewMatcherBuilder()
    if b.HookCount(PrimitiveDiscovery) != 0 || b.HasHooks(PrimitiveDiscovery) {
        t.Fatalf("unexpected initial hooks state")
    }
    b.RegisterCompilationHook(PrimitiveDiscovery, func(_ *CompilationContext) error { return nil })
    if b.HookCount(PrimitiveDiscovery) != 1 || !b.HasHooks(PrimitiveDiscovery) {
        t.Fatalf("expected one hook registered")
    }
    if b.TotalHookCount() != 1 {
        t.Fatalf("total hook count = %d, want 1", b.TotalHookCount())
    }
}

func TestConvenienceHookAhoCorasick(t *testing.T) {
    var mu sync.Mutex
    extracted := make([]string, 0)

    b := NewMatcherBuilder().WithAhoCorasickExtraction(func(lit string, _ float64) error {
        mu.Lock()
        extracted = append(extracted, lit)
        mu.Unlock()
        return nil
    })

    if !b.HasHooks(PrimitiveDiscovery) {
        t.Fatalf("expected PrimitiveDiscovery hook to be present")
    }

    prims := []ir.Primitive{
        ir.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil),
    }
    if _, err := b.Compile(prims); err != nil {
        t.Fatalf("Compile error: %v", err)
    }

    mu.Lock()
    defer mu.Unlock()
    if len(extracted) != 1 || extracted[0] != "4624" {
        t.Fatalf("extracted = %#v, want [\"4624\"]", extracted)
    }
}

func TestSelectivityCalculation(t *testing.T) {
    b := NewMatcherBuilder()
    eq := ir.NewPrimitiveStatic("field", "equals", []string{"v"}, nil)
    if s := b.selectivityHint(&eq); s != 0.1 {
        t.Fatalf("equals selectivity = %v, want 0.1", s)
    }
    contains := ir.NewPrimitiveStatic("field", "contains", []string{"v"}, nil)
    if s := b.selectivityHint(&contains); s != 0.3 {
        t.Fatalf("contains selectivity = %v, want 0.3", s)
    }
    regex := ir.NewPrimitiveStatic("field", "regex", []string{".*"}, nil)
    if s := b.selectivityHint(&regex); s != 0.5 {
        t.Fatalf("regex selectivity = %v, want 0.5", s)
    }
}

func TestBuilderLiteralOnlyDetection(t *testing.T) {
    b := NewMatcherBuilder()
    literal := ir.NewPrimitiveStatic("field", "equals", []string{"literal"}, nil)
    if !b.isLiteralOnly(&literal) {
        t.Fatalf("expected literal-only true")
    }
    wildcard := ir.NewPrimitiveStatic("field", "equals", []string{"test*"}, nil)
    if b.isLiteralOnly(&wildcard) {
        t.Fatalf("expected literal-only false for wildcard")
    }
    re := ir.NewPrimitiveStatic("field", "regex", []string{".*"}, nil)
    if b.isLiteralOnly(&re) {
        t.Fatalf("expected literal-only false for regex")
    }
}
