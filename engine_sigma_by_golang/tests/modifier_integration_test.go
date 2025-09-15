package tests

import (
    "fmt"
    "testing"

    comp "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/matcher"
)

// Mirrors sigma-engine/tests/modifier_integration_test.rs

func TestComprehensiveModifiersRegistration(t *testing.T) {
    matchReg := make(map[string]matcher.MatchFn)
    modReg := make(map[string]matcher.ModifierFn)

    // Register defaults + comprehensive modifiers
    matcher.RegisterDefaults(matchReg, modReg)
    matcher.RegisterComprehensiveModifiers(modReg)

    expected := []string{
        "base64_decode",
        "base64",
        "url_decode",
        "url_encode",
        "html_decode",
        "utf16_decode",
        "utf16le_decode",
        "utf16be_decode",
        "wide_decode",
        "lowercase",
        "uppercase",
        "trim",
        "reverse",
        "normalize_whitespace",
        "normalize_path",
        "basename",
        "dirname",
        "hex_decode",
        "hex_encode",
        "to_int",
        "to_float",
        "md5",
        "sha1",
        "sha256",
    }
    for _, name := range expected {
        if _, ok := modReg[name]; !ok {
            t.Fatalf("missing modifier: %s", name)
        }
    }
    if len(modReg) < 25 {
        t.Fatalf("expected at least 25 modifiers, got %d", len(modReg))
    }
}

func TestModifierFunctionality(t *testing.T) {
    modReg := make(map[string]matcher.ModifierFn)
    matcher.RegisterComprehensiveModifiers(modReg)

    if fn, ok := modReg["base64_decode"]; ok {
        out, err := fn("aGVsbG8=")
        if err != nil || out != "hello" {
            t.Fatalf("base64_decode => %q, %v; want 'hello'", out, err)
        }
    } else { t.Fatalf("base64_decode not registered") }

    if fn, ok := modReg["hex_encode"]; ok {
        out, err := fn("hello")
        if err != nil || out != "68656c6c6f" {
            t.Fatalf("hex_encode => %q, %v; want 68656c6c6f", out, err)
        }
    } else { t.Fatalf("hex_encode not registered") }

    if fn, ok := modReg["uppercase"]; ok {
        out, err := fn("hello")
        if err != nil || out != "HELLO" {
            t.Fatalf("uppercase => %q, %v; want HELLO", out, err)
        }
    } else { t.Fatalf("uppercase not registered") }

    if fn, ok := modReg["trim"]; ok {
        out, err := fn("  hello  ")
        if err != nil || out != "hello" {
            t.Fatalf("trim => %q, %v; want 'hello'", out, err)
        }
    } else { t.Fatalf("trim not registered") }
}

func TestModifierBuilderIntegration(t *testing.T) {
    b := matcher.NewMatcherBuilder()
    modReg := make(map[string]matcher.ModifierFn)
    matcher.RegisterComprehensiveModifiers(modReg)

    keys := []string{"base64_decode", "hex_encode", "uppercase", "trim"}
    for _, k := range keys {
        fn, ok := modReg[k]
        if !ok { t.Fatalf("missing modifier %s in registry", k) }
        // Register into builder
        b.RegisterModifier(k, fn)
    }

    for _, k := range keys {
        if !b.HasModifier(k) { t.Fatalf("builder missing modifier %s", k) }
    }
    if b.HasModifier("nonexistent_modifier") {
        t.Fatalf("builder should not have nonexistent_modifier")
    }
}

func TestCompilerModifierParsing(t *testing.T) {
    // Helper compiles a single selection with field spec and returns the primitive
    compileOne := func(fieldSpec string) (field, matchType string, modifiers []string) {
        c := comp.New()
        rule := fmt.Sprintf(`
title: T
detection:
  selection:
    %s: value
  condition: selection
`, fieldSpec)
        if _, err := c.CompileRule(rule); err != nil {
            t.Fatalf("CompileRule error for %s: %v", fieldSpec, err)
        }
        prims := c.Primitives()
        if len(prims) == 0 { t.Fatalf("no primitives compiled for %s", fieldSpec) }
        p := prims[len(prims)-1]
        return p.Field, p.MatchType, append([]string(nil), p.Modifiers...)
    }

    cases := []struct{
        in string
        f  string
        mt string
        mods []string
    }{
        {"Image", "Image", "equals", nil},
        {"Image|endswith", "Image", "endswith", nil},
        {"CommandLine|contains", "CommandLine", "contains", nil},
        {"User|cased", "User", "equals", []string{"case_sensitive"}},
        {"Hash|re", "Hash", "regex", nil},
        {"Data|base64", "Data", "equals", []string{"base64_decode"}},
        {"Data|utf16", "Data", "equals", []string{"utf16_decode"}},
        {"Data|wide", "Data", "equals", []string{"wide_decode"}},
        {"Data|contains|base64|cased", "Data", "contains", []string{"base64_decode","case_sensitive"}},
    }
    for _, tc := range cases {
        f, mt, mods := compileOne(tc.in)
        if f != tc.f { t.Fatalf("field mismatch for %s: got %s want %s", tc.in, f, tc.f) }
        if mt != tc.mt { t.Fatalf("match type mismatch for %s: got %s want %s", tc.in, mt, tc.mt) }
        if len(mods) != len(tc.mods) { t.Fatalf("mods len for %s: got %v want %v", tc.in, mods, tc.mods) }
        for i := range mods {
            if mods[i] != tc.mods[i] { t.Fatalf("mods[%d] for %s: got %s want %s", i, tc.in, mods[i], tc.mods[i]) }
        }
    }
}

func TestModifierErrorHandling(t *testing.T) {
    modReg := make(map[string]matcher.ModifierFn)
    matcher.RegisterComprehensiveModifiers(modReg)

    if fn, ok := modReg["base64_decode"]; ok {
        if _, err := fn("invalid_base64!"); err == nil {
            t.Fatalf("invalid base64 should return error")
        }
    } else { t.Fatalf("missing base64_decode") }

    if fn, ok := modReg["hex_decode"]; ok {
        if _, err := fn("invalid_hex"); err == nil {
            t.Fatalf("invalid hex should return error")
        }
    } else { t.Fatalf("missing hex_decode") }

    if fn, ok := modReg["to_int"]; ok {
        if _, err := fn("not_a_number"); err == nil {
            t.Fatalf("invalid integer should return error")
        }
    } else { t.Fatalf("missing to_int") }
}
