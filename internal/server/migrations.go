package server

import (
    "context"
    "fmt"
    "io/fs"
    "os"
    "path/filepath"
    "sort"
    "strings"
    "time"
)

// RunMigrations executes all SQL files in the given directory in lexicographic order.
// Each file may contain multiple statements separated by ';'. Simple and robust for CI/demo.
func (s *AppServer) RunMigrations(dir string) error {
    entries := make([]string, 0)
    walkFn := func(path string, d fs.DirEntry, err error) error {
        if err != nil { return err }
        if d.IsDir() { return nil }
        if strings.HasSuffix(strings.ToLower(d.Name()), ".sql") {
            entries = append(entries, path)
        }
        return nil
    }
    if err := filepath.WalkDir(dir, walkFn); err != nil { return err }
    sort.Strings(entries)
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    for _, p := range entries {
        b, err := os.ReadFile(p)
        if err != nil { return fmt.Errorf("read migration %s: %w", p, err) }
        sqlText := string(b)
        // naive split by ';' keeping it simple; ignore empty tail chunks
        chunks := strings.Split(sqlText, ";")
        for _, c := range chunks {
            stmt := strings.TrimSpace(c)
            if stmt == "" { continue }
            if _, err := s.db.ExecContext(ctx, stmt); err != nil {
                return fmt.Errorf("exec migration %s: %w", p, err)
            }
        }
    }
    return nil
}

