package sigma

// Operators cho predicate
type Operator int

const (
	OpEq Operator = iota
	OpNeq
	OpContains
	OpStartsWith
	OpEndsWith
	OpRegex
	OpExists       // field tồn tại (true) / không tồn tại (false)
	OpCidr         // giá trị là CIDR "192.168.1.0/24" hoặc list
	OpLt           // numeric
	OpLte
	OpGt
	OpGte
	OpAll          // đặc thù: field là []any, mọi phần tử chứa needle (contains-all-on-field-list)
)

// Cờ modifier phát sinh từ "Field|mod1|mod2"
type PredicateModifiers struct {
	CaseSensitive  bool   // cased
	Wide           bool   // wide (UTF-16LE NUL interleaved)
	UTF16LE        bool   // utf16le (tương tự wide)
	Base64         bool   // encode mẫu thành base64
	Base64Offset   bool   // tạo 3 biến thể base64 với offset 0..2
	Windash        bool   // chuẩn hoá '-' vs '/' vs en/em dash
	FieldRef       bool   // so sánh với giá trị của field khác (Value là tên field)
	RequireAllVals bool   // với list values: true => tất cả phải match (all-of), false => any-of
}

// Predicate đơn
type SelectionPredicate struct {
	Field     string
	Op        Operator
	Value     any // string|number|bool|[]any
	Modifiers PredicateModifiers
}

// Một group là AND của nhiều predicate
type SelectionGroup struct {
	Predicates []SelectionPredicate
}

// Một selection là OR các group (list → nhiều group; mapping → 1 group)
type Selection struct {
	Name   string
	Groups []SelectionGroup
}

// Rule IR
type RuleIR struct {
	ID         string
	Title      string
	Logsource  map[string]any
	Selections map[string]Selection
	Condition  string
	Literals   map[string]struct{} // literal strings cho prefilter
}
