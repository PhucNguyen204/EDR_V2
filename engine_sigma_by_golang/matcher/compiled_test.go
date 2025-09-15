package matcher

import (
	"fmt"
	"testing"
	"strings"
	"encoding/json"
	ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// match fn test: exact
func testMatchFnExact() MatchFn {
	return func(fieldValue string, values []string, _ []string) (bool, error) {
		for _, v := range values {
			if fieldValue == v {
				return true, nil
			}
		}
		return false, nil
	}
}

// modifier fn test (không dùng trong Matches — để test HasModifiers)
func testModifierUpper() ModifierFn {
	return func(input string) (string, error) {
		return stringsToUpper(input), nil
	}
}

func stringsToUpper(s string) string { // tách để dễ test
	return fmt.Sprintf("%s", string([]rune(s)))
}
func NewEventContextFromMap(m map[string]any) *EventContext {
	return NewEventContext(m)
}

// Optional: tiện cho test khi có JSON thô.
func NewEventContextFromJSON(b []byte) (*EventContext, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return NewEventContext(v), nil
}
func TestCompiledPrimitiveCreation(t *testing.T) {
	cp := NewCompiledPrimitive(
		[]string{"EventID"},
		testMatchFnExact(),
		nil,
		[]string{"4624", "4625"},
		nil,
	)

	if got := cp.FieldPathString(); got != "EventID" {
		t.Fatalf("FieldPathString = %q, want %q", got, "EventID")
	}
	if cp.ValueCount() != 2 {
		t.Fatalf("ValueCount = %d, want 2", cp.ValueCount())
	}
	if cp.HasModifiers() {
		t.Fatal("HasModifiers = true, want false")
	}
	if !cp.IsLiteralOnly() {
		t.Fatal("IsLiteralOnly = false, want true")
	}
}

func TestNestedFieldPath(t *testing.T) {
	cp := NewCompiledPrimitive(
		[]string{"nested", "field"},
		testMatchFnExact(),
		nil,
		[]string{"value"},
		nil,
	)
	if got := cp.FieldPathString(); got != "nested.field" {
		t.Fatalf("FieldPathString = %q, want %q", got, "nested.field")
	}
}

func TestWithModifiersMeta(t *testing.T) {
	cp := NewCompiledPrimitive(
		[]string{"EventID"},
		testMatchFnExact(),
		[]ModifierFn{testModifierUpper()},
		[]string{"4624"},
		[]string{"uppercase"},
	)
	if !cp.HasModifiers() {
		t.Fatal("HasModifiers = false, want true")
	}
	if len(cp.rawModifiers) != 1 || cp.rawModifiers[0] != "uppercase" {
		t.Fatalf("rawModifiers unexpected: %v", cp.rawModifiers)
	}
}

func TestLiteralOnlyDetection(t *testing.T) {
	cp1 := NewCompiledPrimitive(
		[]string{"EventID"},
		testMatchFnExact(),
		nil,
		[]string{"4624", "literal_value"},
		nil,
	)
	if !cp1.IsLiteralOnly() {
		t.Fatal("IsLiteralOnly = false, want true")
	}

	cp2 := NewCompiledPrimitive(
		[]string{"EventID"},
		testMatchFnExact(),
		nil,
		[]string{"test*", "literal"},
		nil,
	)
	if cp2.IsLiteralOnly() {
		t.Fatal("IsLiteralOnly = true, want false (has wildcard)")
	}
}

func TestMemoryUsage(t *testing.T) {
	cp := NewCompiledPrimitive(
		[]string{"EventID"},
		testMatchFnExact(),
		nil,
		[]string{"4624"},
		nil,
	)
	usage := cp.MemoryUsage()
	if usage <= 0 {
		t.Fatal("MemoryUsage <= 0, want > 0")
	}
	// Ít nhất phải >= tổng độ dài chuỗi
	min := len("EventID") + len("4624")
	if usage < min {
		t.Fatalf("MemoryUsage = %d, want >= %d", usage, min)
	}
}

func TestDebugString(t *testing.T) {
	cp := NewCompiledPrimitive(
		[]string{"EventID"},
		testMatchFnExact(),
		nil,
		[]string{"4624"},
		nil,
	)
	s := cp.String()
	if !stringsContainsAll(s, []string{"CompiledPrimitive", "EventID", "4624"}) {
		t.Fatalf("debug string missing fields: %s", s)
	}
}

func TestCloneSemantics(t *testing.T) {
	cp := NewCompiledPrimitive(
		[]string{"EventID"},
		testMatchFnExact(),
		nil,
		[]string{"4624"},
		nil,
	)
	// clone theo kiểu copy struct
	cloned := *cp
	if cloned.FieldPathString() != cp.FieldPathString() {
		t.Fatalf("clone field path mismatch: %s vs %s", cloned.FieldPathString(), cp.FieldPathString())
	}
	if cloned.ValueCount() != cp.ValueCount() {
		t.Fatalf("clone value count mismatch: %d vs %d", cloned.ValueCount(), cp.ValueCount())
	}
}

func TestFromPrimitive(t *testing.T) {
	irp := ir.Primitive{
		Field:     "EventID",
		MatchType: "equals",
		Values:    []string{"4624"},
		Modifiers: nil,
	}
	cp, err := FromPrimitive(irp)
	if err != nil {
		t.Fatalf("FromPrimitive error: %v", err)
	}
	if cp.FieldPathString() != "EventID" {
		t.Fatalf("FieldPathString = %s", cp.FieldPathString())
	}
	// kiểm tra match fn hoạt động
	ctx := NewEventContextFromMap(map[string]any{
		"EventID": "4624",
	})
	if !cp.Matches(ctx) {
		t.Fatal("Matches = false, want true")
	}
}

// -------- helpers cho test --------

func stringsContainsAll(s string, subs []string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
