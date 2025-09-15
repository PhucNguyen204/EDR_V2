package engine_sigma_by_golang

import (
	"testing"
	"fmt"
	"reflect"
	"strings"
)




func TestPrimitiveCreation(t *testing.T) {
	prim := NewPrimitive(
		"EventID",
		"equals",
		[]string{"4624"},
		[]string{},
	)

	if prim.Field != "EventID" {
		t.Fatalf("field mismatch")
	}
	if prim.MatchType != "equals" {
		t.Fatalf("match_type mismatch")
	}
	if len(prim.Values) != 1 || prim.Values[0] != "4624" {
		t.Fatalf("values mismatch: %#v", prim.Values)
	}
	if len(prim.Modifiers) != 0 {
		t.Fatalf("modifiers should be empty")
	}
}

func TestPrimitiveStaticCreation(t *testing.T) {
	prim := NewPrimitiveStatic(
		"EventID",
		"equals",
		[]string{"4624", "4625"},
		[]string{"case_insensitive"},
	)

	if prim.Field != "EventID" {
		t.Fatalf("field mismatch")
	}
	if prim.MatchType != "equals" {
		t.Fatalf("match_type mismatch")
	}
	if len(prim.Values) != 2 || prim.Values[0] != "4624" || prim.Values[1] != "4625" {
		t.Fatalf("values mismatch: %#v", prim.Values)
	}
	if len(prim.Modifiers) != 1 || prim.Modifiers[0] != "case_insensitive" {
		t.Fatalf("modifiers mismatch: %#v", prim.Modifiers)
	}
}

func TestPrimitiveFromStrsCreation(t *testing.T) {
	prim := PrimitiveFromStrs(
		"EventID",
		"equals",
		[]string{"4624", "4625"},
		[]string{"case_insensitive"},
	)

	if prim.Field != "EventID" {
		t.Fatalf("field mismatch")
	}
	if prim.MatchType != "equals" {
		t.Fatalf("match_type mismatch")
	}
	if len(prim.Values) != 2 || prim.Values[0] != "4624" || prim.Values[1] != "4625" {
		t.Fatalf("values mismatch: %#v", prim.Values)
	}
	if len(prim.Modifiers) != 1 || prim.Modifiers[0] != "case_insensitive" {
		t.Fatalf("modifiers mismatch: %#v", prim.Modifiers)
	}
}

func TestCompiledRuleset(t *testing.T) {
	rs := NewCompiledRuleset()
	if rs.PrimitiveCount() != 0 {
		t.Fatalf("expected count 0")
	}

	prim := NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil)
	rs.PrimitiveMap[prim.Key()] = 0
	rs.Primitives = append(rs.Primitives, prim.Clone())

	if rs.PrimitiveCount() != 1 {
		t.Fatalf("expected count 1")
	}
	if got, ok := rs.GetPrimitive(0); !ok || !reflect.DeepEqual(got, prim) {
		t.Fatalf("GetPrimitive(0) mismatch: got=%#v ok=%v", got, ok)
	}
	if _, ok := rs.GetPrimitive(1); ok {
		t.Fatalf("GetPrimitive(1) should be none")
	}
}

func TestPrimitiveEqualityAndHashing(t *testing.T) {
	prim1 := NewPrimitive("EventID", "equals", []string{"4624"}, []string{"case_insensitive"})
	prim2 := NewPrimitive("EventID", "equals", []string{"4624"}, []string{"case_insensitive"})
	prim3 := NewPrimitive("EventID", "equals", []string{"4625"}, []string{"case_insensitive"})

	// Equality (nội dung)
	if !reflect.DeepEqual(prim1, prim2) {
		t.Fatalf("prim1 != prim2")
	}
	if reflect.DeepEqual(prim1, prim3) {
		t.Fatalf("prim1 == prim3")
	}
	if reflect.DeepEqual(prim2, prim3) {
		t.Fatalf("prim2 == prim3")
	}

	// HashMap theo nội dung → dùng key chuỗi ổn định
	m := map[string]PrimitiveId{}
	m[prim1.Key()] = 0
	m[prim2.Key()] = 1 // overwrite
	m[prim3.Key()] = 2

	if len(m) != 2 {
		t.Fatalf("expected 2 unique keys, got %d", len(m))
	}
	if m[prim1.Key()] != 1 || m[prim2.Key()] != 1 {
		t.Fatalf("overwrite failed: m[prim1]=%d m[prim2]=%d", m[prim1.Key()], m[prim2.Key()])
	}
	if m[prim3.Key()] != 2 {
		t.Fatalf("value for prim3 wrong")
	}
}

func TestPrimitiveClone(t *testing.T) {
	prim := NewPrimitive("EventID", "equals",
		[]string{"4624", "4625"},
		[]string{"case_insensitive"},
	)
	cloned := prim.Clone()

	if !reflect.DeepEqual(prim, cloned) {
		t.Fatalf("clone mismatch")
	}
	// sửa cloned.Values không được ảnh hưởng prim.Values (deep copy)
	cloned.Values[0] = "XXXX"
	if prim.Values[0] != "4624" {
		t.Fatalf("clone should be deep: prim.Values mutated")
	}
}

func TestPrimitiveDebugFormat(t *testing.T) {
	prim := NewPrimitive("EventID", "equals", []string{"4624"}, []string{"case_insensitive"})
	// %+v in ra tên trường; hoặc có thể dùng json.Marshal, nhưng theo spirit test Rust: chỉ cần chứa các mảnh.
	debugStr := fmt.Sprintf("%+v", prim)
	wantSubs := []string{"EventID", "equals", "4624", "case_insensitive"}
	for _, sub := range wantSubs {
		if !strings.Contains(debugStr, sub) {
			t.Fatalf("debug string missing %q: %s", sub, debugStr)
		}
	}
}


func TestPrimitiveEmptyValuesAndModifiers(t *testing.T) {
	prim := NewPrimitive("EventID", "exists", []string{}, []string{})
	if prim.Field != "EventID" {
		t.Fatalf("field mismatch")
	}
	if prim.MatchType != "exists" {
		t.Fatalf("match_type mismatch")
	}
	if len(prim.Values) != 0 {
		t.Fatalf("values should be empty")
	}
	if len(prim.Modifiers) != 0 {
		t.Fatalf("modifiers should be empty")
	}
}

func TestPrimitiveMultipleValuesAndModifiers(t *testing.T) {
	prim := NewPrimitive(
		"EventID", "equals",
		[]string{"4624", "4625", "4648"},
		[]string{"case_insensitive", "trim"},
	)

	if !reflect.DeepEqual(prim.Values, []string{"4624", "4625", "4648"}) {
		t.Fatalf("values mismatch: %#v", prim.Values)
	}
	if !reflect.DeepEqual(prim.Modifiers, []string{"case_insensitive", "trim"}) {
		t.Fatalf("modifiers mismatch: %#v", prim.Modifiers)
	}
}


func TestCompiledRulesetMultiplePrimitives(t *testing.T) {
	rs := NewCompiledRuleset()

	prim1 := NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil)
	prim2 := NewPrimitiveStatic("LogonType", "equals", []string{"2"}, nil)
	prim3 := NewPrimitiveStatic("TargetUserName", "contains", []string{"admin"}, []string{"case_insensitive"})

	rs.PrimitiveMap[prim1.Key()] = 0
	rs.PrimitiveMap[prim2.Key()] = 1
	rs.PrimitiveMap[prim3.Key()] = 2

	rs.Primitives = append(rs.Primitives, prim1.Clone(), prim2.Clone(), prim3.Clone())

	if rs.PrimitiveCount() != 3 {
		t.Fatalf("expected count 3, got %d", rs.PrimitiveCount())
	}

	if got, ok := rs.GetPrimitive(0); !ok || !reflect.DeepEqual(got, prim1) {
		t.Fatalf("get 0 mismatch: %#v ok=%v", got, ok)
	}
	if got, ok := rs.GetPrimitive(1); !ok || !reflect.DeepEqual(got, prim2) {
		t.Fatalf("get 1 mismatch: %#v ok=%v", got, ok)
	}
	if got, ok := rs.GetPrimitive(2); !ok || !reflect.DeepEqual(got, prim3) {
		t.Fatalf("get 2 mismatch: %#v ok=%v", got, ok)
	}
	if _, ok := rs.GetPrimitive(3); ok {
		t.Fatalf("get 3 should be none")
	}
	if _, ok := rs.GetPrimitive(999); ok {
		t.Fatalf("get 999 should be none")
	}
}

func TestCompiledRulesetClone(t *testing.T) {
	// Test này giả định bạn đã có method Clone() cho CompiledRuleset như bản gợi ý trước.
	rs := NewCompiledRuleset()
	prim := NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil)
	rs.PrimitiveMap[prim.Key()] = 0
	rs.Primitives = append(rs.Primitives, prim.Clone())

	cloned := rs.Clone()
	if cloned.PrimitiveCount() != 1 {
		t.Fatalf("clone count mismatch")
	}
	if got, ok := cloned.GetPrimitive(0); !ok || !reflect.DeepEqual(got, prim) {
		t.Fatalf("clone get mismatch: %#v ok=%v", got, ok)
	}
	if len(cloned.PrimitiveMap) != 1 {
		t.Fatalf("clone map size mismatch")
	}

	// Sửa cloned không ảnh hưởng rs
	cloned.Primitives[0].Values[0] = "XXXX"
	if got, _ := rs.GetPrimitive(0); got.Values[0] != "4624" {
		t.Fatalf("ruleset clone should be deep")
	}
}

func TestCompiledRulesetDebugFormat(t *testing.T) {
	rs := NewCompiledRuleset()
	prim := NewPrimitiveStatic("EventID", "equals", []string{"4624"}, nil)
	rs.PrimitiveMap[prim.Key()] = 0
	rs.Primitives = append(rs.Primitives, prim.Clone())

	// Không kỳ vọng tên kiểu; chỉ cần chứa tên trường chính.
	debugStr := fmt.Sprintf("%+v", rs)
	if !(strings.Contains(debugStr, "PrimitiveMap") && strings.Contains(debugStr, "Primitives")) {
		t.Fatalf("debug string missing fields: %s", debugStr)
	}
}

func TestPrimitiveIdAndRuleIdTypes(t *testing.T) {
	var primitiveID PrimitiveId = 42
	// Ghi chú: bản bạn dán đang dùng RUleId (typo). Dùng đúng alias hiện có để test biên dịch.
	var ruleID RuleId = 123

	if primitiveID != 42 {
		t.Fatalf("primitive id value mismatch")
	}
	if ruleID != 123 {
		t.Fatalf("rule id value mismatch")
	}

	primitiveIDs := []PrimitiveId{0, 1, 2}
	// và với RUleId
	ruleIDs := []RuleId{100, 200, 300}

	if len(primitiveIDs) != 3 || len(ruleIDs) != 3 {
		t.Fatalf("length mismatch")
	}
}