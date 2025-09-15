package matcher

import (
    "sync"
    "testing"

    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

func TestWithFSTExtraction(t *testing.T) {
    type rec struct{
        field string
        pattern string
        isLiteral bool
    }
    var mu sync.Mutex
    got := make([]rec, 0)

    b := NewMatcherBuilder().WithFSTExtraction(func(field, pattern string, isLiteral bool) error {
        mu.Lock(); got = append(got, rec{field, pattern, isLiteral}); mu.Unlock()
        return nil
    })

    prims := []ir.Primitive{
        ir.NewPrimitiveStatic("User.Name", "equals", []string{"alice","bob"}, nil),
    }
    if _, err := b.Compile(prims); err != nil {
        t.Fatalf("Compile error: %v", err)
    }

    mu.Lock(); defer mu.Unlock()
    if len(got) != 2 {
        t.Fatalf("expected 2 patterns, got %d", len(got))
    }
    for _, r := range got {
        if r.field != "User.Name" || !r.isLiteral {
            t.Fatalf("unexpected record: %+v", r)
        }
    }
}

func TestWithFilterExtraction(t *testing.T) {
    var mu sync.Mutex
    pats := make([]string, 0)

    b := NewMatcherBuilder().WithFilterExtraction(func(pattern string, _ float64) error {
        mu.Lock(); pats = append(pats, pattern); mu.Unlock(); return nil
    })

    prims := []ir.Primitive{
        ir.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil),
        ir.NewPrimitiveStatic("Message", "regex", []string{".*"}, nil),
    }
    if _, err := b.Compile(prims); err != nil {
        t.Fatalf("Compile error: %v", err)
    }

    mu.Lock(); defer mu.Unlock()
    if len(pats) != 1 || pats[0] != "4624" {
        t.Fatalf("expected [4624], got %#v", pats)
    }
}

func TestCompilePhaseHooks(t *testing.T) {
    var pre, post int
    b := NewMatcherBuilder()
    b.RegisterCompilationHook(PreCompilation, func(_ *CompilationContext) error { pre++; return nil })
    b.RegisterCompilationHook(PostCompilation, func(_ *CompilationContext) error { post++; return nil })

    if _, err := b.Compile(nil); err != nil {
        t.Fatalf("Compile error: %v", err)
    }
    if pre != 1 || post != 1 {
        t.Fatalf("expected pre=1, post=1; got %d, %d", pre, post)
    }
}

