//go:build aho
// +build aho

package dag

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	ac "github.com/petar-dambovaliev/aho-corasick" // go get github.com/petar-dambovaliev/aho-corasick

	engine "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

//
// High-performance literal prefilter for DAG optimization.
// Port từ Rust: dùng Aho–Corasick để lọc sự kiện nhanh trên tập pattern literal.
//

// -------------------- Statistics --------------------

type PrefilterStats struct {
	// Tổng số pattern trong automaton
	PatternCount int `json:"pattern_count"`
	// Không còn track theo field (search toàn JSON)
	FieldCount int `json:"field_count"`
	// Số primitive đóng góp pattern
	PrimitiveCount int `json:"primitive_count"`
	// Ước tính selectivity (0.0 = rất chọn lọc, 1.0 = khớp tất)
	EstimatedSelectivity float64 `json:"estimated_selectivity"`
	// Ước lượng footprint bộ nhớ
	MemoryUsage int `json:"memory_usage"`
}

func (s PrefilterStats) IsEffective() bool {
	// >= 5 pattern và selectivity < 0.7
	return s.PatternCount >= 5 && s.EstimatedSelectivity < 0.7
}

func (s PrefilterStats) ShouldEnablePrefilter() bool {
	// >= 1 pattern và selectivity < 0.8
	return s.PatternCount >= 1 && s.EstimatedSelectivity < 0.8
}

func (s PrefilterStats) PerformanceSummary() string {
	if s.PatternCount == 0 {
		return "No patterns - prefilter disabled"
	}
	gain := (1.0 - s.EstimatedSelectivity) * 100.0
	switch {
	case s.EstimatedSelectivity < 0.3:
		return fmt.Sprintf("High selectivity (%.1f%%) - excellent performance gains expected", gain)
	case s.EstimatedSelectivity < 0.6:
		return fmt.Sprintf("Medium selectivity (%.1f%%) - good performance gains expected", gain)
	default:
		return fmt.Sprintf("Low selectivity (%.1f%%) - minimal performance gains expected", gain)
	}
}

func (s PrefilterStats) StrategyName() string {
	return fmt.Sprintf("AhoCorasick (%d patterns)", s.PatternCount)
}

// -------------------- Config --------------------

type PrefilterConfig struct {
	// Bật khớp ASCII case-insensitive trong AC
	CaseInsensitive bool `json:"case_insensitive"`
	// Bỏ qua pattern quá ngắn
	MinPatternLength int `json:"min_pattern_length"`
	// Giới hạn số pattern (nil = no limit)
	MaxPatterns *int `json:"max_patterns"`
	// Công tắc tổng
	Enabled bool `json:"enabled"`
}

func DefaultPrefilterConfig() PrefilterConfig {
	max := 1000
	return PrefilterConfig{
		CaseInsensitive:  false,
		MinPatternLength: 1,
		MaxPatterns:      &max,
		Enabled:          true,
	}
}

func SigmaPrefilterConfig() PrefilterConfig {
	max := 1500
	return PrefilterConfig{
		CaseInsensitive:  false, // SIGMA thường case-sensitive
		MinPatternLength: 1,
		MaxPatterns:      &max,
		Enabled:          true,
	}
}

func DisabledPrefilterConfig() PrefilterConfig {
	cfg := DefaultPrefilterConfig()
	cfg.Enabled = false
	return cfg
}

// -------------------- Prefilter --------------------

type LiteralPrefilter struct {
	// Automaton AC (nil nếu không có pattern)
	ac *ac.AhoCorasick
	// Toàn bộ pattern (giữ nguyên raw để debug/hiển thị)
	patterns []string
	// Map: chỉ số pattern (theo mảng patterns) -> danh sách PrimitiveId sử dụng pattern
	patternToPrimitives map[int][]engine.PrimitiveId
	// Thống kê
	stats PrefilterStats
	// Cấu hình đã dùng để build
	cfg PrefilterConfig
}

func (p *LiteralPrefilter) Stats() PrefilterStats { return p.stats }

// -------------------- Builder nội bộ --------------------

type patternBuilder struct {
	cfg PrefilterConfig

	// Dedupe theo "pattern key" (phân biệt hoa/thường tùy CaseInsensitive)
	dedupe map[string]int // key -> index in combined
	// Mảng pattern raw (đưa vào AC theo thứ tự đã push)
	combined []string
	// Mapping từ chỉ số combined -> các PrimitiveId
	patternToPrimitives map[int][]engine.PrimitiveId

	primitiveCount int
}

func newPatternBuilder(cfg PrefilterConfig) *patternBuilder {
	return &patternBuilder{
		cfg:                 cfg,
		dedupe:              make(map[string]int),
		combined:            make([]string, 0),
		patternToPrimitives: make(map[int][]engine.PrimitiveId),
	}
}

func (pb *patternBuilder) keyFor(pattern string) string {
	if pb.cfg.CaseInsensitive {
		return strings.ToLower(pattern)
	}
	return pattern
}

func (pb *patternBuilder) addPrimitive(primID engine.PrimitiveId, prim engine.Primitive) {
	pb.primitiveCount++

	if !isLiteralMatchType(prim.MatchType) {
		return
	}
	if !hasNoRegexMeta(prim) {
		return
	}

	for _, v := range prim.Values {
		if len(v) < pb.cfg.MinPatternLength {
			continue
		}
		key := pb.keyFor(v)

		idx, ok := pb.dedupe[key]
		if !ok {
			// thêm pattern mới
			idx = len(pb.combined)
			pb.combined = append(pb.combined, v)
			pb.dedupe[key] = idx
		}
		pb.patternToPrimitives[idx] = append(pb.patternToPrimitives[idx], primID)

		// enforce max patterns nếu có
		if pb.cfg.MaxPatterns != nil && len(pb.combined) >= *pb.cfg.MaxPatterns {
			return
		}
	}
}

func (pb *patternBuilder) build() LiteralPrefilter {
	total := len(pb.combined)

	stats := PrefilterStats{
		PatternCount:         total,
		FieldCount:           0,
		PrimitiveCount:       pb.primitiveCount,
		EstimatedSelectivity: estimateSelectivity(total),
		MemoryUsage:          estimateMemoryUsage(total),
	}

	var automaton *ac.AhoCorasick
	if pb.cfg.Enabled && total > 0 {
		opts := ac.Opts{
			AsciiCaseInsensitive: pb.cfg.CaseInsensitive,
			// Các tùy chọn khác có thể bật lên thành config nếu bạn muốn:
			// MatchOnlyWholeWords:  false,
			// DFA:                  false,
			MatchKind: ac.LeftMostLongestMatch, // gần với LeftmostFirst/LeftmostLongest của Rust
		}
		builder := ac.NewAhoCorasickBuilder(opts)
		acBuilt := builder.Build(pb.combined) // index pattern của AC == index trong combined
		automaton = &acBuilt
	}

	return LiteralPrefilter{
		ac:                  automaton,
		patterns:            append([]string(nil), pb.combined...),
		patternToPrimitives: pb.patternToPrimitives,
		stats:               stats,
		cfg:                 pb.cfg,
	}
}

// -------------------- Public API --------------------

// Tạo prefilter từ tập primitives (dùng DefaultPrefilterConfig)
func PrefilterFromPrimitives(prims []engine.Primitive) LiteralPrefilter {
	return PrefilterWithConfig(prims, DefaultPrefilterConfig())
}

// Tạo prefilter với cấu hình custom
func PrefilterWithConfig(prims []engine.Primitive, cfg PrefilterConfig) LiteralPrefilter {
	if !cfg.Enabled {
		return LiteralPrefilter{
			ac:                  nil,
			patterns:            nil,
			patternToPrimitives: map[int][]engine.PrimitiveId{},
			stats: PrefilterStats{
				PatternCount:         0,
				FieldCount:           0,
				PrimitiveCount:       0,
				EstimatedSelectivity: 1.0,
				MemoryUsage:          0,
			},
			cfg: cfg,
		}
	}

	pb := newPatternBuilder(cfg)
	for i, p := range prims {
		if isSuitableForPrefiltering(p) {
			pb.addPrimitive(engine.PrimitiveId(i), p)
		}
	}
	return pb.build()
}

// Evaluate trên JSON đã parse (map[string]any/[]any/string/number/bool/nil)
// Không có pattern => cho qua (true)
func (p *LiteralPrefilter) MatchesJSON(event any) bool {
	if p.stats.PatternCount == 0 || p.ac == nil {
		return true
	}
	return p.searchJSONValueAC(event)
}

// Evaluate trên raw JSON string (nhanh nhất nếu đã có string)
func (p *LiteralPrefilter) MatchesRaw(jsonStr string) bool {
	if p.stats.PatternCount == 0 || p.ac == nil {
		return true
	}
	// AC sẽ xử lý case-insensitive theo config khi build
	return len(p.ac.FindAll(jsonStr)) > 0
}

// Fast path boolean trên chuỗi bất kỳ
func (p *LiteralPrefilter) HasMatch(text string) bool {
	if p.stats.PatternCount == 0 || p.ac == nil {
		return false
	}
	return len(p.ac.FindAll(text)) > 0
}

// Trả về danh sách match (debug/analysis)
// Chuyển event sang JSON string để AC scan một lần
func (p *LiteralPrefilter) FindMatches(event any) []PrefilterMatch {
	out := make([]PrefilterMatch, 0)
	if p.stats.PatternCount == 0 || p.ac == nil {
		return out
	}
	b, _ := json.Marshal(event)
	text := string(b)

	for _, m := range p.ac.FindAll(text) {
		idx := m.Pattern()
		pat := ""
		if idx >= 0 && idx < len(p.patterns) {
			pat = p.patterns[idx]
		}
		ids := p.patternToPrimitives[idx]
		out = append(out, PrefilterMatch{
			Field:        "event",
			Pattern:      pat,
			Start:        m.Start(),
			End:          m.End(),
			PrimitiveIDs: append([]engine.PrimitiveId(nil), ids...),
		})
	}
	return out
}

// -------------------- Nội bộ: JSON traversal + heuristics --------------------

// Duyệt JSON đã parse và áp AC vào string/number/bool, dừng sớm nếu khớp
func (p *LiteralPrefilter) searchJSONValueAC(v any) bool {
	switch x := v.(type) {
	case string:
		return p.HasMatch(x)
	case json.Number:
		return p.HasMatch(x.String())
	case float64:
		return p.HasMatch(strconv.FormatFloat(x, 'g', -1, 64))
	case int, int32, int64:
		return p.HasMatch(fmt.Sprintf("%v", x))
	case uint, uint32, uint64:
		return p.HasMatch(fmt.Sprintf("%v", x))
	case bool:
		if x {
			return p.HasMatch("true")
		}
		return p.HasMatch("false")
	case nil:
		return false
	case []any:
		for _, it := range x {
			if p.searchJSONValueAC(it) {
				return true
			}
		}
		return false
	case map[string]any:
		for _, it := range x {
			if p.searchJSONValueAC(it) {
				return true
			}
		}
		return false
	default:
		// kiểu lạ → marshal rồi scan
		b, _ := json.Marshal(x)
		return p.MatchesRaw(string(b))
	}
}

// -------------------- Helpers/Heuristics --------------------

type PrefilterMatch struct {
	Field        string                 `json:"field"`
	Pattern      string                 `json:"pattern"`
	Start        int                    `json:"start"`
	End          int                    `json:"end"`
	PrimitiveIDs []engine.PrimitiveId   `json:"primitive_ids"`
}

func (m PrefilterMatch) Len() int      { return m.End - m.Start }
func (m PrefilterMatch) IsEmpty() bool { return m.Start == m.End }
func (m PrefilterMatch) MatchedText(src string) (string, bool) {
	if m.Start < 0 || m.End > len(src) || m.Start > m.End {
		return "", false
	}
	return src[m.Start:m.End], true
}

func isLiteralMatchType(mt string) bool {
	switch mt {
	case "equals", "contains", "startswith", "endswith":
		return true
	default:
		return false
	}
}

func isSuitableForPrefiltering(p engine.Primitive) bool {
	if !isLiteralMatchType(p.MatchType) {
		return false
	}
	return hasNoRegexMeta(p)
}

func hasNoRegexMeta(p engine.Primitive) bool {
	var bad []rune
	switch p.MatchType {
	case "endswith", "startswith":
		bad = []rune{'*', '?', '[', ']', '^', '$', '(', ')', '|', '+', '{', '}'}
	default:
		bad = []rune{'*', '?', '[', ']', '^', '$', '\\', '(', ')', '|', '+', '{', '}'}
	}
outer:
	for _, v := range p.Values {
		for _, c := range v {
			for _, b := range bad {
				if c == b {
					return false
				}
			}
		}
		continue outer
	}
	return true
}

func estimateSelectivity(patternCount int) float64 {
	switch {
	case patternCount == 0:
		return 1.0
	case patternCount >= 50:
		return 0.05
	case patternCount >= 20:
		return 0.10
	case patternCount >= 10:
		return 0.20
	case patternCount >= 5:
		return 0.40
	default:
		return 0.70
	}
}

func estimateMemoryUsage(patternCount int) int {
	// Ước lượng thô kiểu Rust
	stateCount := patternCount * 2
	transitionOverhead := stateCount * 256
	stateOverhead := stateCount * 32
	patternOverhead := patternCount * 20
	return patternOverhead + transitionOverhead + stateOverhead
}
