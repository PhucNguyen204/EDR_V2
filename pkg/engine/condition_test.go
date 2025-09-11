package engine

import "testing"

func TestCondition_SimpleID(t *testing.T) {
	ctx := map[string]bool{"selection": true}
	ok, err := EvalCondition("selection", ctx)
	if err != nil || !ok {
		t.Fatalf("expected true, got %v err=%v", ok, err)
	}
}

func TestCondition_PrecedenceAndParens(t *testing.T) {
	ctx := map[string]bool{"a": true, "b": false, "c": true}
	// not > and > or
	ok, _ := EvalCondition("a or b and not c", ctx) 
	if !ok { t.Fatalf("expected true") }

	ok, _ = EvalCondition("a and (b or not c)", ctx) 
	if ok { t.Fatalf("expected false") }

	ok, _ = EvalCondition("(a and not b) or (b and c)", ctx) // (true && true) || (false && true) = true
	if !ok { t.Fatalf("expected true") }
}

func TestCondition_NofPrefix_AllOfPrefix(t *testing.T) {
	ctx := map[string]bool{"sel1": true, "sel2": false, "sel3": true}
	ok, _ := EvalCondition("2 of sel*", ctx)
	if !ok { t.Fatalf("2 of sel* should be true") }

	ok, _ = EvalCondition("all of sel*", map[string]bool{"sel1": true, "sel2": true})
	if !ok { t.Fatalf("all of sel* should be true") }

	ok, _ = EvalCondition("all of sel*", map[string]bool{"sel1": true, "sel2": false})
	if ok { t.Fatalf("all of sel* should be false") }
}

func TestCondition_NofThem_AllOfThem(t *testing.T) {
	ctx := map[string]bool{"a": true, "b": true, "c": false}
	ok, _ := EvalCondition("2 of them", ctx) // a,b true => 2
	if !ok { t.Fatalf("2 of them should be true") }

	ok, _ = EvalCondition("all of them", map[string]bool{"x": true, "y": true})
	if !ok { t.Fatalf("all of them should be true") }

	ok, _ = EvalCondition("all of them", map[string]bool{"x": true, "y": false})
	if ok { t.Fatalf("all of them should be false") }
}

func TestCondition_Unknown_Unbalanced(t *testing.T) {
	ok, _ := EvalCondition("unknown", map[string]bool{})
	if ok { t.Fatalf("unknown should be false") }

	if _, err := EvalCondition("a and (b or c", map[string]bool{}); err == nil {
		t.Fatalf("expected error for unbalanced parens")
	}
}

func TestCondition_WhitespaceAndOpsCase(t *testing.T) {
	ok, _ := EvalCondition("  s  AnD  nOt ( s and  false_id ) ", map[string]bool{"s": true})
	if !ok { t.Fatalf("whitespace/case handling failed") }
}
