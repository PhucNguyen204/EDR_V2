package server

import (
    "context"
    "fmt"
    "os"
    "path/filepath"

    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
)

// LoadRulesFromDir walks a directory recursively, compiles all .yml/.yaml files
// into a single ruleset, builds a new DAG engine, and swaps it.
// Returns (loaded_count, skipped_count, error).
func (s *AppServer) LoadRulesFromDir(_ context.Context, dir string) (int, int, error) {
    c := compiler.New()
    loaded, skipped := 0, 0

    err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
        if err != nil { return err }
        if d.IsDir() { return nil }
        ext := filepath.Ext(d.Name())
        if ext != ".yml" && ext != ".yaml" {
            return nil
        }
        b, rerr := os.ReadFile(path)
        if rerr != nil {
            skipped++
            return nil
        }
        if _, rerr := c.CompileRule(string(b)); rerr != nil {
            // Skip unsupported rules but keep going
            skipped++
            return nil
        }
        loaded++
        return nil
    })
    if err != nil { return loaded, skipped, fmt.Errorf("walk dir: %w", err) }

    rs := c.IntoRuleset()
    newEngine, err := dag.FromRuleset(rs, dag.DefaultEngineConfig())
    if err != nil { return loaded, skipped, err }
    s.swapEngine(newEngine)
    return loaded, skipped, nil
}

