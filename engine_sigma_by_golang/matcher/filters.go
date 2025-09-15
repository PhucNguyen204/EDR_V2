package matcher

import (
	"errors"
	"sort"
	"sync"

	engine "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// Thống kê trong quá trình compile filters
type FilterCompilationStats struct {
	TotalPrimitives    int
	LiteralPrimitives  int
	RegexPrimitives    int
	UniqueFields       int
	AverageSelectivity float64
	EstimatedMemBytes  int
}

// Trợ lý tích hợp filters (Aho-Corasick/FST/Bloom/XOR...)
type FilterIntegration struct {
	// Aho-Corasick
	AhoCorasickPatterns []string
	// group theo field
	FieldPatterns map[string][]string
	// FST (được sort + dedup khi lấy ra)
	FSTValues []string
	// Giá trị chung cho probabilistic filters
	FilterValues []string
	// Regex riêng
	RegexPatterns []string
	// Bloom/XOR
	BloomFilterValues []string
	XORFilterValues   []string
	// “Zero-copy” pattern (giữ reference hằng)
	ZeroCopyPatterns []string

	// Hints/telemetry
	SelectivityMap   map[string]float64 // pattern -> selectivity
	PatternFrequency map[string]int     // pattern -> freq
	FieldFrequency   map[string]int     // field  -> freq

	CompilationStats FilterCompilationStats
}

func NewFilterIntegration() *FilterIntegration {
	return &FilterIntegration{
		AhoCorasickPatterns: make([]string, 0),
		FieldPatterns:       make(map[string][]string),
		FSTValues:           make([]string, 0),
		FilterValues:        make([]string, 0),
		RegexPatterns:       make([]string, 0),
		BloomFilterValues:   make([]string, 0),
		XORFilterValues:     make([]string, 0),
		ZeroCopyPatterns:    make([]string, 0),
		SelectivityMap:      make(map[string]float64),
		PatternFrequency:    make(map[string]int),
		FieldFrequency:      make(map[string]int),
	}
}

func (f *FilterIntegration) AddAhoCorasickPattern(pattern string, fieldOpt *string, selectivity float64) {
	if !containsStr(f.AhoCorasickPatterns, pattern) {
		f.AhoCorasickPatterns = append(f.AhoCorasickPatterns, pattern)
	}
	if fieldOpt != nil {
		field := *fieldOpt
		f.FieldPatterns[field] = append(f.FieldPatterns[field], pattern)
		f.FieldFrequency[field]++
	}
	f.SelectivityMap[pattern] = selectivity
	f.PatternFrequency[pattern]++
}

func (f *FilterIntegration) AddFSTValue(value string, selectivity float64) {
	if !containsStr(f.FSTValues, value) {
		f.FSTValues = append(f.FSTValues, value)
	}
	f.SelectivityMap[value] = selectivity
}

func (f *FilterIntegration) AddFilterValue(value string, selectivity float64) {
	if !containsStr(f.FilterValues, value) {
		f.FilterValues = append(f.FilterValues, value)
	}
	f.SelectivityMap[value] = selectivity
}

func (f *FilterIntegration) AddRegexPattern(pattern string, fieldOpt *string, selectivity float64) {
	if !containsStr(f.RegexPatterns, pattern) {
		f.RegexPatterns = append(f.RegexPatterns, pattern)
	}
	if fieldOpt != nil {
		f.FieldFrequency[*fieldOpt]++
	}
	f.SelectivityMap[pattern] = selectivity
}

func (f *FilterIntegration) AddBloomFilterValue(value string, selectivity float64) {
	if !containsStr(f.BloomFilterValues, value) {
		f.BloomFilterValues = append(f.BloomFilterValues, value)
	}
	f.SelectivityMap[value] = selectivity
	f.PatternFrequency[value]++
}

func (f *FilterIntegration) AddXORFilterValue(value string, selectivity float64) {
	if !containsStr(f.XORFilterValues, value) {
		f.XORFilterValues = append(f.XORFilterValues, value)
	}
	f.SelectivityMap[value] = selectivity
	f.PatternFrequency[value]++
}

func (f *FilterIntegration) AddZeroCopyPattern(pattern string, selectivity float64) {
	if !containsStr(f.ZeroCopyPatterns, pattern) {
		f.ZeroCopyPatterns = append(f.ZeroCopyPatterns, pattern)
	}
	f.SelectivityMap[pattern] = selectivity
	f.PatternFrequency[pattern]++
}

// Tạo hook để tự động lấp dữ liệu vào FilterIntegration trong lúc compile.
// Dùng mutex bên ngoài để thread-safe khi builder chạy song song.
func CreateCompilationHook(integration *FilterIntegration, mu *sync.Mutex) CompilationHookFn {
	return func(ctx *CompilationContext) error {
		if integration == nil {
			return errors.New("nil integration")
		}
		if mu != nil {
			mu.Lock()
			defer mu.Unlock()
		}

		// cập nhật stats
		integration.CompilationStats.TotalPrimitives++
		if stringsEq(ctx.MatchType, "regex") {
			integration.CompilationStats.RegexPrimitives++
		} else {
			integration.CompilationStats.LiteralPrimitives++
		}

		sel := integration.estimateSelectivityFromContext(ctx)
		field := &ctx.NormalizedField

		switch {
		case stringsEq(ctx.MatchType, "equals") ||
			stringsEq(ctx.MatchType, "contains") ||
			stringsEq(ctx.MatchType, "startswith") ||
			stringsEq(ctx.MatchType, "endswith"):
			if ctx.IsLiteralOnly {
				for _, v := range ctx.LiteralValues {
					// AC
					integration.AddAhoCorasickPattern(v, field, sel)
					// FST nếu khá selective
					if sel < 0.3 {
						integration.AddFSTValue(v, sel)
					}
					// XOR nếu rất selective và equals
					if sel <= 0.1 && stringsEq(ctx.MatchType, "equals") {
						integration.AddXORFilterValue(v, sel)
					}
					// Bloom nếu tương đối selective
					if sel < 0.5 {
						integration.AddBloomFilterValue(v, sel)
					}
				}
			} else {
				for _, v := range ctx.LiteralValues {
					integration.AddFilterValue(v, sel)
				}
			}
		case stringsEq(ctx.MatchType, "regex"):
			for _, v := range ctx.LiteralValues {
				integration.AddRegexPattern(v, field, sel)
			}
		default:
			for _, v := range ctx.LiteralValues {
				integration.AddFilterValue(v, sel)
			}
		}

		// cập nhật thống kê fields duy nhất
		integration.CompilationStats.UniqueFields = len(integration.FieldPatterns)
		// cập nhật avg selectivity gần đúng
		integration.CompilationStats.AverageSelectivity = integration.calculateAverageSelectivity()
		return nil
	}
}

// Bulk extract
func (f *FilterIntegration) ExtractFromPrimitives(prims []engine.Primitive) error {
	for i := range prims {
		if err := f.ExtractFromPrimitive(&prims[i]); err != nil {
			return err
		}
	}
	return nil
}

// Per-primitive extraction
func (f *FilterIntegration) ExtractFromPrimitive(p *engine.Primitive) error {
	sel := f.estimateSelectivity(p)
	field := p.Field

	f.CompilationStats.TotalPrimitives++
	if stringsEq(p.MatchType, "regex") {
		f.CompilationStats.RegexPrimitives++
	} else {
		f.CompilationStats.LiteralPrimitives++
	}

	switch {
	case stringsEq(p.MatchType, "equals"),
		stringsEq(p.MatchType, "contains"),
		stringsEq(p.MatchType, "startswith"),
		stringsEq(p.MatchType, "endswith"):
		for _, v := range p.Values {
			f.AddAhoCorasickPattern(v, &field, sel)
			if sel < 0.3 {
				f.AddFSTValue(v, sel)
			}
			if sel <= 0.1 && stringsEq(p.MatchType, "equals") {
				f.AddXORFilterValue(v, sel)
			}
			if sel < 0.5 {
				f.AddBloomFilterValue(v, sel)
			}
			if sel <= 0.1 {
				f.AddFilterValue(v, sel)
			}
		}
	case stringsEq(p.MatchType, "regex"):
		for _, v := range p.Values {
			f.AddRegexPattern(v, &field, sel)
		}
	default:
		for _, v := range p.Values {
			f.AddFilterValue(v, sel)
		}
	}

	f.CompilationStats.UniqueFields = len(f.FieldPatterns)
	f.CompilationStats.AverageSelectivity = f.calculateAverageSelectivity()
	return nil
}

// Lấy patterns đã sort (freq giảm dần, cùng freq thì selectivity tăng dần)
func (f *FilterIntegration) GetAhoCorasickPatterns() []string {
	out := append([]string(nil), f.AhoCorasickPatterns...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		fa := f.PatternFrequency[a]
		fb := f.PatternFrequency[b]
		if fa != fb {
			return fa > fb
		}
		sa := f.SelectivityMap[a]
		sb := f.SelectivityMap[b]
		return sa < sb
	})
	return out
}

// Trả về FST values (đã sort + dedup)
func (f *FilterIntegration) GetFSTValues() []string {
	out := append([]string(nil), f.FSTValues...)
	sort.Strings(out)
	out = dedupSorted(out)
	return out
}

func (f *FilterIntegration) GetFieldPatterns() map[string][]string {
	return f.FieldPatterns
}

func (f *FilterIntegration) GetSelectivePatterns(maxSel float64) []string {
	res := make([]string, 0)
	for _, v := range f.FilterValues {
		if sel, ok := f.SelectivityMap[v]; ok && sel <= maxSel {
			res = append(res, v)
		}
	}
	return res
}

// Thống kê gộp để tối ưu
type FilterStatistics struct {
	TotalPatterns       int
	TotalFSTValues      int
	TotalFilterValues   int
	TotalRegexPatterns  int
	UniqueFields        int
	AvgSelectivity      float64
	MostFrequentField   *string
	PatternDistribution map[string]int
}

func (f *FilterIntegration) GetStatistics() FilterStatistics {
	return FilterStatistics{
		TotalPatterns:       len(f.AhoCorasickPatterns),
		TotalFSTValues:      len(f.FSTValues),
		TotalFilterValues:   len(f.FilterValues),
		TotalRegexPatterns:  len(f.RegexPatterns),
		UniqueFields:        len(f.FieldPatterns),
		AvgSelectivity:      f.calculateAverageSelectivity(),
		MostFrequentField:   f.getMostFrequentField(),
		PatternDistribution: f.getPatternDistribution(),
	}
}

func (f *FilterIntegration) GetRegexPatterns() []string      { return f.RegexPatterns }
func (f *FilterIntegration) GetBloomFilterValues() []string  { return f.BloomFilterValues }
func (f *FilterIntegration) GetXORFilterValues() []string    { return f.XORFilterValues }
func (f *FilterIntegration) GetZeroCopyPatterns() []string   { return f.ZeroCopyPatterns }
func (f *FilterIntegration) GetCompilationStats() *FilterCompilationStats {
	return &f.CompilationStats
}

// --- helpers ---

func (f *FilterIntegration) estimateSelectivity(p *engine.Primitive) float64 {
	switch {
	case stringsEq(p.MatchType, "equals"):
		return 0.1
	case stringsEq(p.MatchType, "contains"):
		return 0.3
	case stringsEq(p.MatchType, "startswith"), stringsEq(p.MatchType, "endswith"):
		return 0.2
	case stringsEq(p.MatchType, "regex"):
		return 0.5
	case stringsEq(p.MatchType, "cidr"):
		return 0.4
	case stringsEq(p.MatchType, "range"):
		return 0.6
	case stringsEq(p.MatchType, "fuzzy"):
		return 0.7
	default:
		return 0.5
	}
}

func (f *FilterIntegration) estimateSelectivityFromContext(ctx *CompilationContext) float64 {
	base := 0.5
	switch {
	case stringsEq(ctx.MatchType, "equals"):
		base = 0.1
	case stringsEq(ctx.MatchType, "contains"):
		base = 0.3
	case stringsEq(ctx.MatchType, "startswith"), stringsEq(ctx.MatchType, "endswith"):
		base = 0.2
	case stringsEq(ctx.MatchType, "regex"):
		base = 0.5
	case stringsEq(ctx.MatchType, "cidr"):
		base = 0.4
	case stringsEq(ctx.MatchType, "range"):
		base = 0.6
	case stringsEq(ctx.MatchType, "fuzzy"):
		base = 0.7
	}
	modAdj := 1.0
	if len(ctx.Modifiers) > 0 {
		modAdj = 1.2
	}
	valAdj := 1.0 + float64(len(ctx.LiteralValues))*0.1
	s := base * modAdj * valAdj
	if s > 1.0 {
		s = 1.0
	}
	return s
}

func (f *FilterIntegration) calculateAverageSelectivity() float64 {
	if len(f.SelectivityMap) == 0 {
		return 0.0
	}
	sum := 0.0
	for _, v := range f.SelectivityMap {
		sum += v
	}
	return sum / float64(len(f.SelectivityMap))
}

func (f *FilterIntegration) getMostFrequentField() *string {
	var best string
	bestCnt := -1
	for k, c := range f.FieldFrequency {
		if c > bestCnt {
			bestCnt = c
			best = k
		}
	}
	if bestCnt < 0 {
		return nil
	}
	return &best
}

func (f *FilterIntegration) getPatternDistribution() map[string]int {
	return map[string]int{
		"aho_corasick": len(f.AhoCorasickPatterns),
		"fst":          len(f.FSTValues),
		"filter":       len(f.FilterValues),
		"regex":        len(f.RegexPatterns),
		"bloom":        len(f.BloomFilterValues),
		"xor":          len(f.XORFilterValues),
		"zero_copy":    len(f.ZeroCopyPatterns),
	}
}

func containsStr(arr []string, s string) bool {
	for _, x := range arr {
		if x == s {
			return true
		}
	}
	return false
}

func dedupSorted(arr []string) []string {
	if len(arr) == 0 {
		return arr
	}
	out := arr[:1]
	for i := 1; i < len(arr); i++ {
		if arr[i] != arr[i-1] {
			out = append(out, arr[i])
		}
	}
	return out
}

func stringsEq(a, b string) bool {
	// so khớp đơn giản, case-sensitive như Rust
	return a == b
}
