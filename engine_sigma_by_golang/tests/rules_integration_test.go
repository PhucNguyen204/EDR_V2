package tests

import (
    "os"
    "path/filepath"
    "runtime"
    "sort"
    "testing"

    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
)

// resolve rules dir relative to this test file to avoid CWD issues
func rulesDir(t *testing.T) string {
    t.Helper()
    _, file, _, ok := runtime.Caller(0)
    if !ok { t.Fatalf("runtime.Caller failed") }
    return filepath.Join(filepath.Dir(file), "rules")
}

func loadRuleFiles(t *testing.T) []string {
    t.Helper()
    dir := rulesDir(t)
    entries, err := os.ReadDir(dir)
    if err != nil { t.Fatalf("read rules dir: %v", err) }
    names := make([]string, 0, len(entries))
    for _, e := range entries {
        if e.IsDir() { continue }
        if filepath.Ext(e.Name()) == ".yml" || filepath.Ext(e.Name()) == ".yaml" {
            names = append(names, filepath.Join(dir, e.Name()))
        }
    }
    sort.Strings(names)
    return names
}

func readFile(t *testing.T, p string) string {
    t.Helper()
    b, err := os.ReadFile(p)
    if err != nil { t.Fatalf("read %s: %v", p, err) }
    return string(b)
}

// Compile every rule file; malformed_rule.yml must fail; others must compile.
func TestCompileRulesFromFolder(t *testing.T) {
    files := loadRuleFiles(t)
    c := compiler.New()
    okCount := 0
    for _, f := range files {
        yml := readFile(t, f)
        _, err := c.CompileRule(yml)
        base := filepath.Base(f)
        if base == "malformed_rule.yml" {
            if err == nil { t.Fatalf("expected error for %s", base) }
            continue
        }
        if err != nil { t.Fatalf("compile %s: %v", base, err) }
        okCount++
    }
    if okCount == 0 { t.Fatalf("no rule compiled") }
}

// Build DAG from all valid rules; ensure rule results count > 0 and build succeeds.
func TestBuildDagFromCompiledRules(t *testing.T) {
    files := loadRuleFiles(t)
    c := compiler.New()
    valid := 0
    for _, f := range files {
        if filepath.Base(f) == "malformed_rule.yml" { continue }
        if _, err := c.CompileRule(readFile(t, f)); err != nil {
            t.Fatalf("compile %s: %v", f, err)
        }
        valid++
    }
    if valid == 0 { t.Fatalf("no valid rules to build") }
    rs := c.IntoRuleset()
    d, err := dag.NewDagBuilder().FromRuleset(rs).Build()
    if err != nil { t.Fatalf("build dag: %v", err) }
    if d.NodeCount() == 0 { t.Fatalf("dag node count is 0") }
    if len(d.RuleResults) == 0 { t.Fatalf("no rule results in DAG") }
}
