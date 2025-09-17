package matcher

import (
	"encoding/json"
	"fmt"
	"strings"
)

// EventContext cung cấp cache giá trị field cho event JSON để tăng hiệu năng.
// Không an toàn cho concurrent/goroutine: mỗi goroutine nên tạo context riêng.
type EventContext struct {
	// Event gốc đã được unmarshal từ JSON. Thường là map[string]any.
	Event any
	// fieldCache: key là đường dẫn field, value là *string:
	//   - *string != nil  -> Some(value)
	//   - *string == nil  -> None (không tồn tại / null)
	fieldCache map[string]*string
}

// NewEventContext tạo context mới từ object JSON đã được unmarshal.
func NewEventContext(event any) *EventContext {
	return &EventContext{
		Event:      event,
		fieldCache: make(map[string]*string),
	}
}

// GetField trả về (value, ok, err):
// - ok = true  => có giá trị (string) sau khi chuẩn hoá kiểu
// - ok = false => không tồn tại hoặc null
// - err != nil => lỗi khi loại dữ liệu không hỗ trợ (array/object tại node cuối)
func (c *EventContext) GetField(field string) (string, bool, error) {
	// Cache fast-path
	if v, exists := c.fieldCache[field]; exists {
		if v == nil {
			return "", false, nil
		}
		return *v, true, nil
	}

	var (
		val string
		ok  bool
		err error
	)
	if strings.Contains(field, ".") {
		val, ok, err = c.extractNestedField(field)
	} else {
		val, ok, err = c.extractSimpleField(field)
	}
	// Lưu cache
	if err != nil {
		return "", false, err
	}
	if ok {
		c.fieldCache[field] = &val
		return val, true, nil
	}
	c.fieldCache[field] = nil
	return "", false, nil
}

// extractSimpleField tối ưu cho key cấp 1.
func (c *EventContext) extractSimpleField(field string) (string, bool, error) {
	root, ok := c.Event.(map[string]any)
	if !ok {
		// Không phải object => không có key
		return "", false, nil
	}
	v, exists := root[field]
	if !exists {
		return "", false, nil
	}
	return valueToString(v, field, false)
}

// extractNestedField duyệt theo dot-notation.
func (c *EventContext) extractNestedField(fieldPath string) (string, bool, error) {
	current := c.Event
	for _, part := range strings.Split(fieldPath, ".") {
		obj, ok := current.(map[string]any)
		if !ok {
			// Giống serde_json: get(part) trên non-object trả None
			return "", false, nil
		}
		v, exists := obj[part]
		if !exists {
			return "", false, nil
		}
		current = v
	}
	// Node cuối: chuyển về string/none/err
	return valueToString(current, fieldPath, true)
}

// valueToString chuẩn hoá kiểu node cuối về string theo đặc tả:
// - string -> giữ nguyên
// - number/bool -> chuỗi tương ứng
// - nil (JSON null) -> None
// - array/object -> lỗi FieldExtractionError "unsupported type"
func valueToString(v any, fieldName string, nested bool) (string, bool, error) {
	switch t := v.(type) {
	case nil:
		return "", false, nil
	case string:
		return t, true, nil
	case bool:
		if t {
			return "true", true, nil
		}
		return "false", true, nil
	case float64, float32, int, int64, int32, int16, int8, uint, uint64, uint32, uint16, uint8, json.Number:
		return fmt.Sprint(t), true, nil
	case map[string]any, []any:
		// Không hỗ trợ array/object tại node cuối — khớp hành vi Rust
		prefix := "Field"
		if nested {
			prefix = "Nested field"
		}
		return "", false, fmt.Errorf("FieldExtractionError: %s '%s' has unsupported type", prefix, fieldName)
	default:
		// JSON tiêu chuẩn của encoding/json thường không ra kiểu lạ,
		// nhưng ta vẫn fallback an toàn.
		prefix := "Field"
		if nested {
			prefix = "Nested field"
		}
		return "", false, fmt.Errorf("FieldExtractionError: %s '%s' has unsupported type", prefix, fieldName)
	}
}

// AnyValueMatches walks the event recursively and applies the predicate to each scalar value.
func (c *EventContext) AnyValueMatches(match func(string) bool) bool {
	if c == nil {
		return false
	}
	return anyValueMatchesRecursive(c.Event, match)
}

func anyValueMatchesRecursive(node any, match func(string) bool) bool {
	switch t := node.(type) {
	case map[string]any:
		for _, v := range t {
			if anyValueMatchesRecursive(v, match) {
				return true
			}
		}
	case []any:
		for _, v := range t {
			if anyValueMatchesRecursive(v, match) {
				return true
			}
		}
	case string:
		return match(t)
	case bool:
		if t {
			return match("true")
		}
		return match("false")
	case float64, float32, int, int64, int32, int16, int8, uint, uint64, uint32, uint16, uint8, json.Number:
		return match(fmt.Sprint(t))
	case nil:
		return false
	default:
		return false
	}
	return false
}

// ClearCache xoá cache.
func (c *EventContext) ClearCache() {
	c.fieldCache = make(map[string]*string)
}

// CacheSize trả về số lượng key đang cache.
func (c *EventContext) CacheSize() int {
	return len(c.fieldCache)
}
