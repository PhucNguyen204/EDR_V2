// matcher/builder.go
package matcher

import (
    "strings"
    "sync"

    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// MatcherBuilder là builder theo registry pattern cho high-perf matcher.
type MatcherBuilder struct {
	// Registry của matchers theo tên match type
	matchRegistry map[string]MatchFn
	// Registry của modifiers theo tên modifier
	modifierRegistry map[string]ModifierFn

	// Field extractor tuỳ chọn (giữ ở builder để mở rộng; CompiledPrimitive hiện dùng EventContext)
	fieldExtractor FieldExtractorFn

	// Hooks theo pha biên dịch
	compilationHooks map[CompilationPhase][]CompilationHookFn

	mu sync.RWMutex
}

// NewMatcherBuilder tạo builder với các matchers/modifiers mặc định.
func NewMatcherBuilder() *MatcherBuilder {
	b := &MatcherBuilder{
		matchRegistry:     make(map[string]MatchFn),
		modifierRegistry:  make(map[string]ModifierFn),
		compilationHooks:  make(map[CompilationPhase][]CompilationHookFn),
	}
	b.registerDefaults() // equals/contains/startswith/endswith/regex + cidr/range/fuzzy + base64,utf16
	return b
}

// NewMatcherBuilderWithComprehensiveModifiers: dùng full SIGMA modifiers (comprehensive).
func NewMatcherBuilderWithComprehensiveModifiers() *MatcherBuilder {
    b := &MatcherBuilder{
        matchRegistry:     make(map[string]MatchFn),
        modifierRegistry:  make(map[string]ModifierFn),
        compilationHooks:  make(map[CompilationPhase][]CompilationHookFn),
    }
    RegisterDefaultsWithComprehensiveModifiers(b.matchRegistry, b.modifierRegistry)
    return b
}

// RegisterMatch thêm/ghi đè 1 match function cho match type.
func (b *MatcherBuilder) RegisterMatch(matchType string, fn MatchFn) *MatcherBuilder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.matchRegistry[strings.ToLower(matchType)] = fn
	return b
}

// RegisterModifier thêm/ghi đè 1 modifier processor theo tên.
func (b *MatcherBuilder) RegisterModifier(name string, fn ModifierFn) *MatcherBuilder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.modifierRegistry[strings.ToLower(name)] = fn
	return b
}

// WithFieldExtractor đặt custom field extractor (tuỳ chọn).
func (b *MatcherBuilder) WithFieldExtractor(extractor FieldExtractorFn) *MatcherBuilder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fieldExtractor = extractor
	return b
}

// RegisterCompilationHook đăng ký 1 hook chạy ở pha compile.
func (b *MatcherBuilder) RegisterCompilationHook(phase CompilationPhase, hook CompilationHookFn) *MatcherBuilder {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.compilationHooks[phase] = append(b.compilationHooks[phase], hook)
	return b
}

// WithAhoCorasickExtraction: convenience hook trích literal + selectivity.
func (b *MatcherBuilder) WithAhoCorasickExtraction(extractor func(literal string, selectivity float64) error) *MatcherBuilder {
	h := CompilationHookFn(func(ctx *CompilationContext) error {
		if ctx.IsLiteralOnly {
			for _, v := range ctx.LiteralValues {
				if err := extractor(v, ctx.SelectivityHint); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return b.RegisterCompilationHook(PrimitiveDiscovery, h)
}

// WithFSTExtraction: convenience hook trích (field, pattern, isLiteral).
func (b *MatcherBuilder) WithFSTExtraction(extractor func(field, pattern string, isLiteral bool) error) *MatcherBuilder {
	h := CompilationHookFn(func(ctx *CompilationContext) error {
		for _, v := range ctx.LiteralValues {
			if err := extractor(ctx.NormalizedField, v, ctx.IsLiteralOnly); err != nil {
				return err
			}
		}
		return nil
	})
	return b.RegisterCompilationHook(PrimitiveDiscovery, h)
}

// WithFilterExtraction: convenience hook trích (pattern, selectivity) cho probabilistic filters.
func (b *MatcherBuilder) WithFilterExtraction(extractor func(pattern string, selectivity float64) error) *MatcherBuilder {
	h := CompilationHookFn(func(ctx *CompilationContext) error {
		if ctx.IsLiteralOnly {
			for _, v := range ctx.LiteralValues {
				if err := extractor(v, ctx.SelectivityHint); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return b.RegisterCompilationHook(PrimitiveDiscovery, h)
}

// Compile: biên dịch primitives → compiled primitives, chạy hooks theo pha.
func (b *MatcherBuilder) Compile(prims []ir.Primitive) ([]CompiledPrimitive, error) {
    // PreCompilation hooks
    if hs := b.hooks(PreCompilation); len(hs) > 0 {
        name := "Compilation"
        ctx := NewSummaryContext(0, &name)
        for _, h := range hs {
            if err := h(ctx); err != nil {
                return nil, err
            }
        }
	}

	out := make([]CompiledPrimitive, 0, len(prims))
	for i := range prims {
		// PrimitiveDiscovery hooks
		if hs := b.hooks(PrimitiveDiscovery); len(hs) > 0 {
			if err := b.execPrimitiveHooks(&prims[i], uint32(i), hs); err != nil {
				return nil, err
			}
		}
		// Compile từng primitive
		cp, err := b.compileOne(&prims[i])
		if err != nil {
			return nil, err
		}
		out = append(out, cp)
	}

    // PostCompilation hooks
    if hs := b.hooks(PostCompilation); len(hs) > 0 {
        name := "Compilation Complete"
        ctx := NewSummaryContext(0, &name)
        for _, h := range hs {
            if err := h(ctx); err != nil {
                return nil, err
            }
        }
	}

	return out, nil
}

// ---------- helpers ----------

func (b *MatcherBuilder) compileOne(p *ir.Primitive) (CompiledPrimitive, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// field path pre-parse
	fieldPath := strings.Split(p.Field, ".")

	// match fn
	matchFn, ok := b.matchRegistry[strings.ToLower(p.MatchType)]
	if !ok {
		return CompiledPrimitive{}, &UnsupportedMatchTypeError{MatchType: p.MatchType}
	}

	// modifier chain (bỏ qua modifier không có trong registry – giống ghi chú ở Rust)
	modChain := make([]ModifierFn, 0, len(p.Modifiers))
	for _, m := range p.Modifiers {
		if fn, ok := b.modifierRegistry[strings.ToLower(m)]; ok {
			modChain = append(modChain, fn)
		}
	}

	// copy values & raw modifiers
	values := append([]string(nil), p.Values...)
	rawMods := append([]string(nil), p.Modifiers...)

	return *NewCompiledPrimitive(fieldPath, matchFn, modChain, values, rawMods), nil
}

func (b *MatcherBuilder) execPrimitiveHooks(p *ir.Primitive, ruleID uint32, hooks []CompilationHookFn) error {
    lits := append([]string(nil), p.Values...)
    mods := append([]string(nil), p.Modifiers...)

    sel := b.selectivityHint(p)
    literalOnly := b.isLiteralOnly(p)

    ctx := &CompilationContext{
        Primitive:       p,
        RuleID:          ruleID,
        RuleName:        nil,
        LiteralValues:   lits,
        RawField:        p.Field,
        NormalizedField: p.Field,
        MatchType:       p.MatchType,
        Modifiers:       mods,
        IsLiteralOnly:   literalOnly,
        SelectivityHint: sel,
    }

	for _, h := range hooks {
		if err := h(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (b *MatcherBuilder) selectivityHint(p *ir.Primitive) float64 {
	switch strings.ToLower(p.MatchType) {
	case "equals":
		return 0.1
	case "contains":
		return 0.3
	case "startswith", "endswith":
		return 0.2
	case "regex":
		return 0.5
	default:
		return 0.5
	}
}

func (b *MatcherBuilder) isLiteralOnly(p *ir.Primitive) bool {
	switch strings.ToLower(p.MatchType) {
	case "equals", "contains", "startswith", "endswith":
		for _, v := range p.Values {
			if strings.ContainsAny(v, "*?[") || strings.Contains(v, "^") {
				return false
			}
		}
		return true
	case "regex":
		return false
	default:
		return true
	}
}

func (b *MatcherBuilder) registerDefaults() {
	RegisterDefaults(b.matchRegistry, b.modifierRegistry)
}

func (b *MatcherBuilder) hooks(phase CompilationPhase) []CompilationHookFn {
	b.mu.RLock()
	defer b.mu.RUnlock()
	h := b.compilationHooks[phase]
	out := make([]CompilationHookFn, len(h))
	copy(out, h)
	return out
}

// ---------- introspection (phục vụ test/diagnostics) ----------

func (b *MatcherBuilder) MatchTypeCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.matchRegistry)
}

func (b *MatcherBuilder) ModifierCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.modifierRegistry)
}

func (b *MatcherBuilder) HasMatchType(t string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.matchRegistry[strings.ToLower(t)]
	return ok
}

func (b *MatcherBuilder) HasModifier(m string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.modifierRegistry[strings.ToLower(m)]
	return ok
}

func (b *MatcherBuilder) HookCount(phase CompilationPhase) int {
	return len(b.hooks(phase))
}

func (b *MatcherBuilder) HasHooks(phase CompilationPhase) bool {
	return b.HookCount(phase) > 0
}

func (b *MatcherBuilder) TotalHookCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	total := 0
	for _, hs := range b.compilationHooks {
		total += len(hs)
	}
	return total
}

// ---------- lỗi riêng cho UnsupportedMatchType (tương đương SigmaError::UnsupportedMatchType) ----------

type UnsupportedMatchTypeError struct{ MatchType string }

func (e *UnsupportedMatchTypeError) Error() string { return "unsupported match type: " + e.MatchType }
