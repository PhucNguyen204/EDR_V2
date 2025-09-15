package matcher

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustUnmarshal(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	return v
}

func createTestEvent(t *testing.T) any {
	return mustUnmarshal(t, `
{
  "EventID": "4624",
  "LogonType": 2,
  "Success": true,
  "Empty": null
}`)
}

func TestSimpleFieldExtraction(t *testing.T) {
	event := createTestEvent(t)
	ctx := NewEventContext(event)

	if val, ok, err := ctx.GetField("EventID"); err != nil || !ok || val != "4624" {
		t.Fatalf("EventID => want 4624,true,nil got %q,%v,%v", val, ok, err)
	}
	if val, ok, err := ctx.GetField("LogonType"); err != nil || !ok || val != "2" {
		t.Fatalf("LogonType => want 2,true,nil got %q,%v,%v", val, ok, err)
	}
	if val, ok, err := ctx.GetField("Success"); err != nil || !ok || val != "true" {
		t.Fatalf("Success => want true,true,nil got %q,%v,%v", val, ok, err)
	}
	if val, ok, err := ctx.GetField("Empty"); err != nil || ok {
		t.Fatalf("Empty => want '',false,nil got %q,%v,%v", val, ok, err)
	}
	if val, ok, err := ctx.GetField("NonExistent"); err != nil || ok {
		t.Fatalf("NonExistent => want '',false,nil got %q,%v,%v", val, ok, err)
	}
}

func TestNestedFieldExtraction(t *testing.T) {
	event := mustUnmarshal(t, `
{
  "nested": {
    "field": "value",
    "number": 42,
    "deep": {
      "value": "deep_value"
    }
  }
}`)
	ctx := NewEventContext(event)

	if val, ok, err := ctx.GetField("nested.field"); err != nil || !ok || val != "value" {
		t.Fatalf("nested.field => want value,true,nil got %q,%v,%v", val, ok, err)
	}
	if val, ok, err := ctx.GetField("nested.number"); err != nil || !ok || val != "42" {
		t.Fatalf("nested.number => want 42,true,nil got %q,%v,%v", val, ok, err)
	}
	if val, ok, err := ctx.GetField("nested.deep.value"); err != nil || !ok || val != "deep_value" {
		t.Fatalf("nested.deep.value => want deep_value,true,nil got %q,%v,%v", val, ok, err)
	}
	if val, ok, err := ctx.GetField("nested.nonexistent"); err != nil || ok {
		t.Fatalf("nested.nonexistent => want '',false,nil got %q,%v,%v", val, ok, err)
	}
	if val, ok, err := ctx.GetField("nonexistent.field"); err != nil || ok {
		t.Fatalf("nonexistent.field => want '',false,nil got %q,%v,%v", val, ok, err)
	}
}

func TestFieldCaching(t *testing.T) {
	event := mustUnmarshal(t, `{"EventID":"4624"}`)
	ctx := NewEventContext(event)

	if sz := ctx.CacheSize(); sz != 0 {
		t.Fatalf("want cache size 0, got %d", sz)
	}
	if val, ok, err := ctx.GetField("EventID"); err != nil || !ok || val != "4624" {
		t.Fatalf("first get => want 4624,true,nil got %q,%v,%v", val, ok, err)
	}
	if sz := ctx.CacheSize(); sz != 1 {
		t.Fatalf("want cache size 1 after first get, got %d", sz)
	}
	if val, ok, err := ctx.GetField("EventID"); err != nil || !ok || val != "4624" {
		t.Fatalf("second get => want 4624,true,nil got %q,%v,%v", val, ok, err)
	}
	if sz := ctx.CacheSize(); sz != 1 {
		t.Fatalf("want cache size still 1, got %d", sz)
	}
}

func TestCacheClear(t *testing.T) {
	event := mustUnmarshal(t, `{"EventID":"4624"}`)
	ctx := NewEventContext(event)

	_, _, _ = ctx.GetField("EventID")
	if sz := ctx.CacheSize(); sz != 1 {
		t.Fatalf("expect cache size 1, got %d", sz)
	}
	ctx.ClearCache()
	if sz := ctx.CacheSize(); sz != 0 {
		t.Fatalf("expect cache size 0 after clear, got %d", sz)
	}
}

func TestUnsupportedFieldType(t *testing.T) {
	event := mustUnmarshal(t, `
{
  "array_field": [1,2,3],
  "object_field": {"key":"value"}
}`)
	ctx := NewEventContext(event)

	if _, _, err := ctx.GetField("array_field"); err == nil || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("array_field => expected unsupported type error, got %v", err)
	}
	if _, _, err := ctx.GetField("object_field"); err == nil || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("object_field => expected unsupported type error, got %v", err)
	}
}
