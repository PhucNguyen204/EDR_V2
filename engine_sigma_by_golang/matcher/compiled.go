package matcher

import (
	"fmt"
	"strings"
	ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"

)

// MatchFn, ModifierFn đã có trong matcher/types.go
// type MatchFn func(fieldValue string, values []string, modifiers []string) (bool, error)
// type ModifierFn func(input string) (string, error)

// CompiledPrimitive đại diện primitive đã biên dịch tối ưu để đánh giá nhanh.
type CompiledPrimitive struct {
	// Các thành phần path đã tách sẵn, vd: ["Event","System","EventID"]
	fieldPath []string

	// Hàm match đã biên dịch
	matchFn MatchFn

	// Chuỗi modifier (đã resolve thành hàm) — hiện tại giữ để tương thích
	modifierChain []ModifierFn

	// Giá trị so khớp
	values []string

	// Tên modifier thô (dùng truyền vào matchFn nếu cần)
	rawModifiers []string
}

// NewCompiledPrimitive tạo primitive đã biên dịch.
func NewCompiledPrimitive(
	fieldPath []string,
	matchFn MatchFn,
	modifierChain []ModifierFn,
	values []string,
	rawModifiers []string,
) *CompiledPrimitive {
	// copy slice để tránh alias ngoài ý muốn
	fp := append([]string(nil), fieldPath...)
	mc := append([]ModifierFn(nil), modifierChain...)
	vs := append([]string(nil), values...)
	rm := append([]string(nil), rawModifiers...)
	return &CompiledPrimitive{
		fieldPath:     fp,
		matchFn:       matchFn,
		modifierChain: mc,
		values:        vs,
		rawModifiers:  rm,
	}
}

// FieldPathString trả về field path dạng "a.b.c".
func (c *CompiledPrimitive) FieldPathString() string {
	return strings.Join(c.fieldPath, ".")
}

// HasModifiers có modifier không?
func (c *CompiledPrimitive) HasModifiers() bool {
	return len(c.modifierChain) > 0
}

// ValueCount số lượng giá trị so khớp.
func (c *CompiledPrimitive) ValueCount() int {
	return len(c.values)
}

// IsLiteralOnly kiểm tra có wildcard đơn giản (*, ?) trong values không.
func (c *CompiledPrimitive) IsLiteralOnly() bool {
	for _, v := range c.values {
		if strings.ContainsAny(v, "*?") {
			return false
		}
	}
	return true
}

// MemoryUsage ước lượng kích thước chuỗi (đơn giản: tổng byte chuỗi).
func (c *CompiledPrimitive) MemoryUsage() int {
	sum := 0
	for _, s := range c.fieldPath {
		sum += len(s)
	}
	for _, s := range c.values {
		sum += len(s)
	}
	for _, s := range c.rawModifiers {
		sum += len(s)
	}
	return sum
}

// Matches đánh giá primitive trên context.
// Lưu ý: tương tự bản Rust đưa ra, ở đây KHÔNG áp dụng modifierChain vào field value.
func (c *CompiledPrimitive) Matches(ctx *EventContext) bool {
	fp := c.FieldPathString()
	val, ok, err := ctx.GetField(fp)
	if err != nil || !ok {
		return false
	}
	ok2, _ := c.matchFn(val, c.values, c.rawModifiers)
	return ok2
}

// FromPrimitive biên dịch từ IR primitive sang CompiledPrimitive.
// Dùng các match-fn mặc định đã có (equals/contains/regex/range/cidr/fuzzy...).
func FromPrimitive(p ir.Primitive) (*CompiledPrimitive, error) {
	// tách field path theo '.'
	var fieldPath []string
	if p.Field != "" {
		fieldPath = strings.Split(p.Field, ".")
	}

	// map match type -> matchFn
	var mf MatchFn
	switch strings.ToLower(p.MatchType) {
	case "equals", "exact":
		mf = createExactMatch()
	case "contains":
		mf = createContainsMatch()
	case "startswith":
		mf = createStartswithMatch()
	case "endswith":
		mf = createEndswithMatch()
	case "regex":
		mf = createRegexMatch()
	case "range":
		mf = createRangeMatch()
	case "cidr":
		mf = createCIDRMatch()
	case "fuzzy":
		mf = createFuzzyMatch()
	default:
		// fallback exact
		mf = createExactMatch()
	}

	// Ghi chú: để đơn giản như bản Rust ví dụ, chưa compile modifierChain thật sự tại đây.
	return NewCompiledPrimitive(fieldPath, mf, nil, p.Values, p.Modifiers), nil
}

// String giúp debug (tương đương Debug trong Rust test).
func (c *CompiledPrimitive) String() string {
	return fmt.Sprintf("CompiledPrimitive{field_path=%q, values=%v, raw_modifiers=%v, has_modifiers=%v, value_count=%d, is_literal_only=%v}",
		c.FieldPathString(), c.values, c.rawModifiers, c.HasModifiers(), c.ValueCount(), c.IsLiteralOnly())
}


