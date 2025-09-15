//go:build aho
// +build aho

package dag

import (
	"strconv"
	"strings"
	"testing"

	engine "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

func TestPrefilterCreation(t *testing.T) {
	primitives := []engine.Primitive{
		engine.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil),
		engine.NewPrimitiveStatic("ProcessName", "contains", []string{"powershell"}, nil),
		// regex -> phải bị bỏ qua
		engine.NewPrimitiveStatic("CommandLine", "regex", []string{".*\\.exe.*"}, nil),
	}

	pref := PrefilterFromPrimitives(primitives)

	stats := pref.Stats()
	if stats.PatternCount != 2 {
		t.Fatalf("pattern_count = %d, want 2", stats.PatternCount)
	}
	if stats.FieldCount != 0 {
		t.Fatalf("field_count = %d, want 0", stats.FieldCount)
	}

	if len(pref.patterns) != 2 {
		t.Fatalf("patterns len = %d, want 2", len(pref.patterns))
	}
	if !(contains(pref.patterns, "4624") && contains(pref.patterns, "powershell")) {
		t.Fatalf("patterns missing expected entries: %v", pref.patterns)
	}
	if pref.ac == nil {
		t.Fatalf("automaton should be built")
	}
}

func TestPrefilterMatching(t *testing.T) {
	primitives := []engine.Primitive{
		engine.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil),
		engine.NewPrimitiveStatic("ProcessName", "contains", []string{"powershell"}, nil),
	}
	pref := PrefilterFromPrimitives(primitives)

	// match
	matchEvent := map[string]any{
		"EventID":     "4624",
		"ProcessName": "explorer.exe",
	}
	if !pref.MatchesJSON(matchEvent) {
		t.Fatalf("should match")
	}

	// non-match
	nonMatch := map[string]any{
		"EventID":     "4625",
		"ProcessName": "explorer.exe",
	}
	if pref.MatchesJSON(nonMatch) {
		t.Fatalf("should NOT match")
	}
}

func TestEmptyPrefilter(t *testing.T) {
	// Chỉ regex -> không có literal pattern
	primitives := []engine.Primitive{
		engine.NewPrimitiveStatic("CommandLine", "regex", []string{".*\\.exe.*"}, nil),
	}
	pref := PrefilterFromPrimitives(primitives)

	// Không có pattern => allow-through
	ev := map[string]any{"test": "value"}
	if !pref.MatchesJSON(ev) {
		t.Fatalf("empty prefilter should allow all")
	}
	if pref.Stats().IsEffective() {
		t.Fatalf("with 0 patterns, IsEffective should be false")
	}
}

func TestNestedFieldExtraction(t *testing.T) {
	// Field name không quan trọng cho prefilter; chỉ cần literal xuất hiện trong JSON
	primitives := []engine.Primitive{
		engine.NewPrimitiveStatic("process.name", "equals", []string{"powershell.exe"}, nil),
	}
	pref := PrefilterFromPrimitives(primitives)

	event := map[string]any{
		"process": map[string]any{
			"name": "powershell.exe",
			"pid":  1234,
		},
	}
	if !pref.MatchesJSON(event) {
		t.Fatalf("nested value should be found")
	}
}

func TestPrefilterConfig(t *testing.T) {
	primitives := []engine.Primitive{
		engine.NewPrimitiveStatic("EventID", "equals", []string{"test", "a"}, nil), // "a" quá ngắn
	}
	cfg := DefaultPrefilterConfig()
	cfg.MinPatternLength = 2

	pref := PrefilterWithConfig(primitives, cfg)
	if pref.Stats().PatternCount != 1 {
		t.Fatalf("pattern_count = %d, want 1", pref.Stats().PatternCount)
	}
	if len(pref.patterns) != 1 || pref.patterns[0] != "test" {
		t.Fatalf("patterns = %v, want [test]", pref.patterns)
	}
}

func TestFindMatches(t *testing.T) {
	primitives := []engine.Primitive{
		engine.NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil),
		engine.NewPrimitiveStatic("ProcessName", "contains", []string{"powershell"}, nil),
	}
	pref := PrefilterFromPrimitives(primitives)

	event := map[string]any{
		"EventID":     "4624",
		"ProcessName": "powershell.exe",
	}
	ms := pref.FindMatches(event)
	if len(ms) != 2 {
		t.Fatalf("FindMatches len = %d, want 2 (got: %+v)", len(ms), ms)
	}
	// kiểm tra chứa đủ 2 pattern
	got := []string{ms[0].Pattern, ms[1].Pattern}
	if !(contains(got, "4624") && contains(got, "powershell")) {
		t.Fatalf("missing expected patterns in matches: %v", got)
	}
}

func TestAhoCorasickPrefilter(t *testing.T) {
	prims := make([]engine.Primitive, 0, 25)
	for i := 0; i < 25; i++ {
		prims = append(prims, engine.NewPrimitive(
			"EventID",
			"equals",
			[]string{("event_" + itoa(i))},
			nil,
		))
	}
	pref := PrefilterFromPrimitives(prims)
	if len(pref.patterns) != 25 {
		t.Fatalf("patterns len = %d, want 25", len(pref.patterns))
	}
	if pref.ac == nil {
		t.Fatalf("automaton should not be nil")
	}

	nonMatch := map[string]any{
		"EventID":     "different_event",
		"ProcessName": "explorer.exe",
	}
	if pref.MatchesJSON(nonMatch) {
		t.Fatalf("non-matching event should be filtered out")
	}

	match := map[string]any{
		"EventID":     "event_5",
		"ProcessName": "explorer.exe",
	}
	if !pref.MatchesJSON(match) {
		t.Fatalf("matching event should pass")
	}
}

func TestPerformanceSummary(t *testing.T) {
	stats := PrefilterStats{
		PatternCount:         10,
		EstimatedSelectivity: 0.2,
	}
	sum := stats.PerformanceSummary()
	if !(strings.Contains(sum, "High selectivity") && strings.Contains(sum, "80.0%")) {
		t.Fatalf("unexpected summary: %s", sum)
	}
}

func TestBenchmarkDataFiltering(t *testing.T) {
	primitives := []engine.Primitive{
		engine.NewPrimitiveStatic("EventID", "equals", []string{"4624", "4625"}, nil),
		engine.NewPrimitiveStatic("ProcessName", "contains", []string{"powershell", "mimikatz"}, nil),
		engine.NewPrimitiveStatic("DestinationIp", "equals", []string{"127.0.0.1"}, nil),
	}
	pref := PrefilterFromPrimitives(primitives)

	// Normal event -> phải bị lọc (không match)
	normal := map[string]any{
		"EventID":       "1",
		"ProcessName":   "explorer.exe",
		"DestinationIP": "192.168.1.1",
	}
	if pref.MatchesJSON(normal) {
		t.Fatalf("normal event should be filtered out (no literal hit)")
	}

	// Suspicious -> pass
	susp := map[string]any{
		"EventID":       "4624",
		"ProcessName":   "powershell.exe",
		"DestinationIP": "10.0.1.1",
	}
	if !pref.MatchesJSON(susp) {
		t.Fatalf("suspicious event should pass prefilter")
	}

	// Ghi chú: event có IP 127.0.0.1 sẽ pass vì có literal đó
	_ = map[string]any{
		"EventID":       "1",
		"ProcessName":   "explorer.exe",
		"DestinationIP": "127.0.0.1",
	}
}

// ---------------- helpers ----------------

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
