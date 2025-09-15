package matcher

import (
	"fmt"

	// TODO: đổi về import thật của bạn, nơi khai báo Primitive.
	engine "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// Hook được gọi tại các pha biên dịch khác nhau.
// Trả về error nếu hook thất bại.
type CompilationHookFn func(ctx *CompilationContext) error

// Các pha biên dịch nơi hook có thể được đăng ký.
type CompilationPhase int

const (
	PrimitiveDiscovery CompilationPhase = iota // phát hiện primitive
	PreCompilation                             // sau khi phát hiện xong, trước compile
	PostCompilation                            // sau khi compile hoàn tất
)

// Ngữ cảnh truyền cho hook trong quá trình compile.
type CompilationContext struct {
	// Primitive đang xử lý
	Primitive *engine.Primitive

	// Rule metadata
	RuleID   uint32
	RuleName *string // nil nếu không có

	// Giá trị literal sau khi áp dụng modifier (nếu có)
	LiteralValues []string

	// Tên field thô và đã chuẩn hoá
	RawField        string
	NormalizedField string

	// Kiểu match và modifiers áp dụng
	MatchType string
	Modifiers []string

	// Cờ/Hint tối ưu
	IsLiteralOnly   bool
	SelectivityHint float64
}

// Tạo context cho một primitive cụ thể.
func NewCompilationContext(
	primitive *engine.Primitive,
	ruleID uint32,
	ruleName *string,
	literalValues []string,
	rawField string,
	normalizedField string,
	matchType string,
	modifiers []string,
	isLiteralOnly bool,
	selectivityHint float64,
) *CompilationContext {
	return &CompilationContext{
		Primitive:       primitive,
		RuleID:          ruleID,
		RuleName:        ruleName,
		LiteralValues:   append([]string(nil), literalValues...),
		RawField:        rawField,
		NormalizedField: normalizedField,
		MatchType:       matchType,
		Modifiers:       append([]string(nil), modifiers...),
		IsLiteralOnly:   isLiteralOnly,
		SelectivityHint: selectivityHint,
	}
}

// Tạo context tóm tắt (không gắn với primitive cụ thể), dùng cho pre/post compilation.
func NewSummaryContext(ruleID uint32, ruleName *string) *CompilationContext {
	placeholder := engine.NewPrimitive("", "", nil, nil) // primitive rỗng (value)
	return &CompilationContext{
		Primitive:       &placeholder,
		RuleID:          ruleID,
		RuleName:        ruleName,
		LiteralValues:   nil,
		RawField:        "",
		NormalizedField: "",
		MatchType:       "",
		Modifiers:       nil,
		IsLiteralOnly:   false,
		SelectivityHint: 0.5,
	}
}

// Có phải context dạng tóm tắt?
func (c *CompilationContext) IsSummary() bool {
	return c.RawField == "" && c.MatchType == ""
}

// Số lượng literal values.
func (c *CompilationContext) LiteralValueCount() int {
	return len(c.LiteralValues)
}

// Primitive có modifiers không?
func (c *CompilationContext) HasModifiers() bool {
	return len(c.Modifiers) > 0
}

// Mô tả ngắn gọn context (debug/log).
func (c *CompilationContext) Description() string {
	if c.IsSummary() {
		name := "unnamed"
		if c.RuleName != nil {
			name = *c.RuleName
		}
		return fmt.Sprintf("Summary context for rule %d (%s)", c.RuleID, name)
	}
	mode := "pattern"
	if c.IsLiteralOnly {
		mode = "literal"
	}
	return fmt.Sprintf(
		"Primitive context: %s %s %s (rule %d, %d values, selectivity: %.2f)",
		c.NormalizedField,
		c.MatchType,
		mode,
		c.RuleID,
		c.LiteralValueCount(),
		c.SelectivityHint,
	)
}
