package matcher

import (
	"sync"
	"testing"

	// TODO: đổi về import thực tế nơi chứa Primitive (ir.go)
	engine "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

func TestFilterIntegrationBasic(t *testing.T) {
	fi := NewFilterIntegration()
	fi.AddAhoCorasickPattern("test", strptr("field1"), 0.1)
	fi.AddFSTValue("value1", 0.2)
	fi.AddFilterValue("filter1", 0.05)

	if len(fi.AhoCorasickPatterns) != 1 || len(fi.FSTValues) != 1 || len(fi.FilterValues) != 1 {
		t.Fatalf("basic add failed")
	}
}

func TestPatternDeduplication(t *testing.T) {
	fi := NewFilterIntegration()
	fi.AddAhoCorasickPattern("duplicate", nil, 0.1)
	fi.AddAhoCorasickPattern("duplicate", nil, 0.1)
	if len(fi.AhoCorasickPatterns) != 1 {
		t.Fatalf("dedup failed")
	}
}

func TestSelectivePatterns(t *testing.T) {
	fi := NewFilterIntegration()
	fi.AddFilterValue("selective", 0.05)
	fi.AddFilterValue("not_selective", 0.8)
	got := fi.GetSelectivePatterns(0.1)
	if len(got) != 1 || got[0] != "selective" {
		t.Fatalf("selective mismatch: %#v", got)
	}
}

func TestPrimitiveExtraction(t *testing.T) {
	fi := NewFilterIntegration()
	p := engine.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil)
	if err := fi.ExtractFromPrimitive(&p); err != nil {
		t.Fatalf("extract err: %v", err)
	}
	if len(fi.AhoCorasickPatterns) == 0 {
		t.Fatalf("expected AC patterns")
	}
	if _, ok := fi.FieldPatterns["EventID"]; !ok {
		t.Fatalf("expected field patterns for EventID")
	}
}

func TestFilterIntegrationComprehensive(t *testing.T) {
	fi := NewFilterIntegration()

	fi.AddAhoCorasickPattern("pattern1", strptr("field1"), 0.3)
	fi.AddAhoCorasickPattern("pattern2", strptr("field2"), 0.7)
	fi.AddFSTValue("value1", 0.4)
	fi.AddFSTValue("value2", 0.8)
	fi.AddFilterValue("filter1", 0.2)
	fi.AddRegexPattern("regex1", nil, 0.6)

	stats := fi.GetStatistics()
	if stats.TotalPatterns != 2 || stats.TotalFSTValues != 2 || stats.TotalFilterValues != 1 || stats.TotalRegexPatterns != 1 || stats.UniqueFields != 2 {
		t.Fatalf("stats mismatch: %#v", stats)
	}

	fp := fi.GetFieldPatterns()
	if len(fp["field1"]) != 1 || len(fp["field2"]) != 1 {
		t.Fatalf("field patterns mismatch: %#v", fp)
	}
}

func TestFilterIntegrationOptimization(t *testing.T) {
	fi := NewFilterIntegration()

	fi.AddAhoCorasickPattern("high_sel", nil, 0.9)
	fi.AddAhoCorasickPattern("med_sel", nil, 0.5)
	fi.AddAhoCorasickPattern("low_sel", nil, 0.1)

	optimized := fi.GetAhoCorasickPatterns()
	if len(optimized) != 3 {
		t.Fatalf("optimized len mismatch")
	}

	// get_selective_patterns dựa trên FilterValues
	fi.AddFilterValue("high_sel", 0.9)
	fi.AddFilterValue("med_sel", 0.5)
	fi.AddFilterValue("low_sel", 0.1)
	sel := fi.GetSelectivePatterns(0.4)
	has := func(s string) bool {
		for _, v := range sel {
			if v == s {
				return true
			}
		}
		return false
	}
	if has("high_sel") || has("med_sel") || !has("low_sel") {
		t.Fatalf("selective filter mismatch: %#v", sel)
	}
}

func TestFilterIntegrationStatistics(t *testing.T) {
	fi := NewFilterIntegration()
	fi.AddAhoCorasickPattern("p1", strptr("common_field"), 0.2)
	fi.AddAhoCorasickPattern("p2", strptr("common_field"), 0.4)
	fi.AddAhoCorasickPattern("p3", strptr("rare_field"), 0.6)

	stats := fi.GetStatistics()
	if stats.UniqueFields != 2 {
		t.Fatalf("unique fields mismatch")
	}
	if stats.MostFrequentField == nil || *stats.MostFrequentField != "common_field" {
		t.Fatalf("most frequent field mismatch: %#v", stats.MostFrequentField)
	}
	if diff(stats.AvgSelectivity, (0.2+0.4+0.6)/3, 1e-3) {
		t.Fatalf("avg selectivity mismatch: %v", stats.AvgSelectivity)
	}
}

func TestFilterIntegrationEmpty(t *testing.T) {
	fi := NewFilterIntegration()
	stats := fi.GetStatistics()
	if stats.TotalPatterns != 0 || stats.TotalFSTValues != 0 || stats.TotalFilterValues != 0 || stats.TotalRegexPatterns != 0 || stats.UniqueFields != 0 {
		t.Fatalf("empty stats mismatch: %#v", stats)
	}
	if len(fi.GetAhoCorasickPatterns()) != 0 {
		t.Fatalf("expected no patterns")
	}
	if len(fi.GetFieldPatterns()) != 0 {
		t.Fatalf("expected no field patterns")
	}
}

func TestPrimitiveExtractionComprehensive(t *testing.T) {
	fi := NewFilterIntegration()
	prims := []engine.Primitive{
		engine.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil),
		engine.NewPrimitiveStatic("ProcessName", "contains", []string{"powershell"}, nil),
		engine.NewPrimitiveStatic("CommandLine", "regex", []string{".*\\.exe.*"}, nil),
	}
	for i := range prims {
		if err := fi.ExtractFromPrimitive(&prims[i]); err != nil {
			t.Fatalf("extract err: %v", err)
		}
	}
	if len(fi.AhoCorasickPatterns) == 0 || len(fi.FieldPatterns) == 0 {
		t.Fatalf("expected extracted patterns")
	}
}

func TestNewFilterTypes(t *testing.T) {
	fi := NewFilterIntegration()
	fi.AddBloomFilterValue("bloom_value", 0.3)
	if len(fi.GetBloomFilterValues()) != 1 || fi.GetBloomFilterValues()[0] != "bloom_value" {
		t.Fatalf("bloom mismatch")
	}
	fi.AddXORFilterValue("xor_value", 0.05)
	if len(fi.GetXORFilterValues()) != 1 || fi.GetXORFilterValues()[0] != "xor_value" {
		t.Fatalf("xor mismatch")
	}
	fi.AddZeroCopyPattern("static_pattern", 0.1)
	if len(fi.GetZeroCopyPatterns()) != 1 || fi.GetZeroCopyPatterns()[0] != "static_pattern" {
		t.Fatalf("zerocopy mismatch")
	}
}

func TestCompilationStats(t *testing.T) {
	fi := NewFilterIntegration()
	prims := []engine.Primitive{
		engine.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil),
		engine.NewPrimitiveStatic("CommandLine", "regex", []string{".*\\.exe.*"}, nil),
	}
	for i := range prims {
		if err := fi.ExtractFromPrimitive(&prims[i]); err != nil {
			t.Fatalf("extract err: %v", err)
		}
	}
	stats := fi.GetCompilationStats()
	if stats.TotalPrimitives != 2 || stats.LiteralPrimitives != 1 || stats.RegexPrimitives != 1 {
		t.Fatalf("compilation stats mismatch: %#v", stats)
	}
}

func TestAutomaticFilterSelection(t *testing.T) {
	// equals -> rất selective -> nhiều filter
	{
		fi := NewFilterIntegration()
		p := engine.Primitive{
			Field:     "EventID",
			MatchType: "equals",
			Values:    []string{"4624"},
		}
		if err := fi.ExtractFromPrimitive(&p); err != nil {
			t.Fatalf("extract err: %v", err)
		}
		if len(fi.AhoCorasickPatterns) == 0 ||
			len(fi.FSTValues) == 0 ||
			len(fi.XORFilterValues) == 0 ||
			len(fi.BloomFilterValues) == 0 ||
			len(fi.FilterValues) == 0 {
			t.Fatalf("expected multi-filter population")
		}
	}
	// contains -> vừa phải -> không vào XOR
	{
		fi := NewFilterIntegration()
		p := engine.Primitive{
			Field:     "ProcessName",
			MatchType: "contains",
			Values:    []string{"powershell"},
		}
		if err := fi.ExtractFromPrimitive(&p); err != nil {
			t.Fatalf("extract err: %v", err)
		}
		if len(fi.AhoCorasickPatterns) == 0 || len(fi.BloomFilterValues) == 0 {
			t.Fatalf("expected AC + Bloom")
		}
		if len(fi.XORFilterValues) != 0 {
			t.Fatalf("should not add XOR for contains")
		}
	}
}

func TestCompilationHookCreation(t *testing.T) {
	fi := NewFilterIntegration()
	var mu sync.Mutex
	hook := CreateCompilationHook(fi, &mu)

	prim := engine.NewPrimitiveStatic("EventID", "equals", []string{"test_value"}, nil)
	ctx := NewCompilationContext(
		&prim,
		1,
		strptr("Test Rule"),
		[]string{"test_value"},
		"EventID",
		"EventID",
		"equals",
		nil,
		true,
		0.1,
	)

	if err := hook(ctx); err != nil {
		t.Fatalf("hook error: %v", err)
	}
	if len(fi.AhoCorasickPatterns) == 0 {
		t.Fatalf("hook didn't populate patterns")
	}
	if fi.CompilationStats.TotalPrimitives != 1 || fi.CompilationStats.LiteralPrimitives != 1 {
		t.Fatalf("hook stats mismatch: %#v", fi.CompilationStats)
	}
}

// --- helpers ---


func diff(a, b, eps float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d > eps
}
