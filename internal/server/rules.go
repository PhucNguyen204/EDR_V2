package server

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
	"github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
	"github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
)

func (s *AppServer) LoadRulesFromDir(ctx context.Context, dir string) (int, int, error) {
	c := compiler.New()
	loaded, skipped := 0, 0
	//duyet de quy
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(d.Name())
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			skipped++
			return nil
		}
		// goi ham compile de kiem tra tinh hop le cua rule (ho tro ca multi-doc & correlation)
		if _, rerr := c.CompileRule(string(b)); rerr != nil {
			skipped++
			return nil
		}
		loaded++
		return nil
	})
	if err != nil {
		return loaded, skipped, fmt.Errorf("walk dir: %w", err)
	}
	// chuyen doi sang ruleset (bao gom correlation)
	rs := c.IntoRuleset()
	// luu metadata//
	s.SetRuleMetaFromRuleset(rs)
	if err := s.UpsertRules(ctx, rs); err != nil {
		return loaded, skipped, fmt.Errorf("upsert rules: %w", err)
	}
	// chuyen doi sang dag engine
	newEngine, err := dag.FromRuleset(rs, dag.DefaultEngineConfig())
	if err != nil {
		return loaded, skipped, err
	}
	s.swapEngine(newEngine)
	log.Printf("rules loaded into DAG: rules=%d nodes=%d primitives=%d prefilter_patterns=%d", newEngine.RuleCount(), newEngine.NodeCount(), newEngine.PrimitiveCount(), newEngine.PrefilterPatternCount())
	return loaded, skipped, nil
}

// them vao db
func (s *AppServer) UpsertRules(ctx context.Context, rs *ir.CompiledRuleset) error {
	for _, r := range rs.Rules {
		uid := r.RuleUID
		if uid == "" {
			uid = fmt.Sprintf("rid-%d", r.RuleId)
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO rules(rule_uid, title, level, description)
            VALUES ($1,$2,$3,$4)
            ON CONFLICT (rule_uid) DO UPDATE SET title=EXCLUDED.title, level=EXCLUDED.level, description=EXCLUDED.description`,
			uid, r.Title, r.Level, r.Description,
		); err != nil {
			return err
		}
	}
	return nil
}
