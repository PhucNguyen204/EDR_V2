package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PhucNguyen204/EDR_V2/internal/rules"
	"github.com/PhucNguyen204/EDR_V2/pkg/sigma"
)

func TestIntegration_DjangoSuspiciousOperation(t *testing.T) {
	p := filepath.Join("..", "..", "internal", "rules", "application", "django", "appframework_django_exceptions.yml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read rule: %v", err)
	}
	r, err := sigma.LoadRuleYAML(b)
	if err != nil {
		t.Fatalf("load rule: %v", err)
	}
	eng := Compile([]sigma.RuleIR{r}, sigma.NewFieldMapping(map[string]string{"message": "Message"}))

	ev := map[string]any{"Message": "Django error: SuspiciousOperation in view"}
	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatalf("evaluate error: %v", err)
	}
	if len(ids) == 0 {
		t.Fatalf("expected match, got none")
	}
}

func TestIntegration_AllRules_DjangoSuspiciousOperation(t *testing.T) {
	rs, err := rules.LoadDirRecursive(filepath.Join("..", "..", "internal", "rules"))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	eng := Compile(rs, sigma.NewFieldMapping(map[string]string{"message": "Message"}))
	ev := map[string]any{"Message": "Django error: SuspiciousOperation in view"}
	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatalf("evaluate error: %v", err)
	}
	if len(ids) == 0 {
		t.Fatalf("expected match with full ruleset, got none")
	}
}
