package rules

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/PhucNguyen204/EDR_V2/pkg/sigma"
)

func isYAML(p string) bool {
	l := strings.ToLower(p)
	return strings.HasSuffix(l, ".yml") || strings.HasSuffix(l, ".yaml")
}

func LoadDirRecursive(root string) ([]sigma.RuleIR, error) {
	var out []sigma.RuleIR
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil { return err }
		if d.IsDir() || !isYAML(p) { return nil }
		b, err := os.ReadFile(p); if err != nil { return err }
		r, err := sigma.LoadRuleYAML(b); if err != nil { return err }
		out = append(out, r)
		return nil
	})
	return out, err
}
