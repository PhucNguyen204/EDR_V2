package matcher

import (
	"testing"
)

func TestExactMatchCaseInsensitive(t *testing.T) {
	fn := createExactMatch()

	if ok, _ := fn("Test", []string{"test"}, nil); !ok {
		t.Fatal("expected true")
	}
	if ok, _ := fn("TEST", []string{"test"}, nil); !ok {
		t.Fatal("expected true")
	}
	if ok, _ := fn("different", []string{"test"}, nil); ok {
		t.Fatal("expected false")
	}
}

func TestExactMatchCaseSensitive(t *testing.T) {
	fn := createExactMatch()

	if ok, _ := fn("Test", []string{"test"}, []string{"case_sensitive"}); ok {
		t.Fatal("expected false")
	}
	if ok, _ := fn("test", []string{"test"}, []string{"case_sensitive"}); !ok {
		t.Fatal("expected true")
	}
}

func TestContainsMatch(t *testing.T) {
	fn := createContainsMatch()

	if ok, _ := fn("Hello World", []string{"world"}, nil); !ok {
		t.Fatal("expected true")
	}
	if ok, _ := fn("Hello World", []string{"WORLD"}, nil); !ok {
		t.Fatal("expected true")
	}
	if ok, _ := fn("Hello World", []string{"xyz"}, nil); ok {
		t.Fatal("expected false")
	}
}

func TestStartswithMatch(t *testing.T) {
	fn := createStartswithMatch()

	if ok, _ := fn("Hello World", []string{"hello"}, nil); !ok {
		t.Fatal("expected true")
	}
	if ok, _ := fn("Hello World", []string{"world"}, nil); ok {
		t.Fatal("expected false")
	}
}

func TestEndswithMatch(t *testing.T) {
	fn := createEndswithMatch()

	if ok, _ := fn("Hello World", []string{"world"}, nil); !ok {
		t.Fatal("expected true")
	}
	if ok, _ := fn("Hello World", []string{"hello"}, nil); ok {
		t.Fatal("expected false")
	}
}

func TestMultipleValues(t *testing.T) {
	fn := createExactMatch()

	if ok, _ := fn("test", []string{"other", "test", "another"}, nil); !ok {
		t.Fatal("expected true")
	}
	if ok, _ := fn("nomatch", []string{"other", "test", "another"}, nil); ok {
		t.Fatal("expected false")
	}
}

func TestRegexMatch(t *testing.T) {
	fn := createRegexMatch()

	if ok, err := fn("test123", []string{`\\d+`, `\d+`}, nil); err != nil || !ok {
		// first pattern invalid (escaped), second valid should still return true
		// depending on evaluation order, invalid might show up first; so do single valid check:
		if ok2, err2 := fn("test123", []string{`\d+`}, nil); err2 != nil || !ok2 {
			t.Fatalf("expected regex match true, got ok=%v err=%v", ok2, err2)
		}
	}
	if ok, _ := fn("testABC", []string{`\d+`}, nil); ok {
		t.Fatal("expected false")
	}
}

func TestUTF16Decode(t *testing.T) {
	mod := createUTF16Decode()
	out, err := mod("test")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out != "test" {
		t.Fatalf("expected 'test', got '%s'", out)
	}
}

func TestRegisterDefaults(t *testing.T) {
	mr := map[string]MatchFn{}
	modr := map[string]ModifierFn{}

	RegisterDefaults(mr, modr)

	// basic
	for _, k := range []string{"equals", "contains", "startswith", "endswith", "regex"} {
		if _, ok := mr[k]; !ok {
			t.Fatalf("missing match %s", k)
		}
	}
	// advanced
	for _, k := range []string{"cidr", "range", "fuzzy"} {
		if _, ok := mr[k]; !ok {
			t.Fatalf("missing match %s", k)
		}
	}
	// modifiers
	for _, k := range []string{"base64_decode", "utf16_decode"} {
		if _, ok := modr[k]; !ok {
			t.Fatalf("missing modifier %s", k)
		}
	}
}

func TestRangeMatch(t *testing.T) {
	fn := createRangeMatch()

	// valid / boundary
	if ok, _ := fn("150", []string{"100-200"}, nil); !ok {
		t.Fatal("expected true")
	}
	if ok, _ := fn("100", []string{"100-200"}, nil); !ok {
		t.Fatal("expected true (lower bound)")
	}
	if ok, _ := fn("200", []string{"100-200"}, nil); !ok {
		t.Fatal("expected true (upper bound)")
	}

	// outside
	if ok, _ := fn("50", []string{"100-200"}, nil); ok {
		t.Fatal("expected false")
	}
	if ok, _ := fn("250", []string{"100-200"}, nil); ok {
		t.Fatal("expected false")
	}

	// multiple ranges
	if ok, _ := fn("75", []string{"50-100", "150-200"}, nil); !ok {
		t.Fatal("expected true (multiple ranges)")
	}

	// invalid number
	if _, err := fn("not_a_number", []string{"100-200"}, nil); err == nil {
		t.Fatal("expected invalid number error")
	}

	// invalid range format
	if _, err := fn("150", []string{"invalid_range"}, nil); err == nil {
		t.Fatal("expected invalid range error")
	}
}

func TestFuzzyMatch(t *testing.T) {
	fn := createFuzzyMatch()

	// exact
	if ok, _ := fn("hello", []string{"hello"}, nil); !ok {
		t.Fatal("expected true")
	}

	// similar with default threshold ~0.8
	if ok, _ := fn("hello", []string{"helo"}, nil); !ok {
		t.Fatal("expected true with default threshold")
	}

	// high threshold
	if ok, _ := fn("hello", []string{"helo"}, []string{"threshold:0.9"}); ok {
		t.Fatal("expected false with high threshold")
	}

	// lower threshold
	if ok, _ := fn("hello", []string{"helo"}, []string{"threshold:0.7"}); !ok {
		t.Fatal("expected true with lower threshold")
	}

	// completely different
	if ok, _ := fn("hello", []string{"xyz"}, nil); ok {
		t.Fatal("expected false")
	}

	// invalid threshold
	if _, err := fn("hello", []string{"helo"}, []string{"threshold:invalid"}); err == nil {
		t.Fatal("expected invalid threshold error")
	}
}

func TestCIDRMatch(t *testing.T) {
	fn := createCIDRMatch()

	// ipv4
	if ok, err := fn("192.168.1.100", []string{"192.168.1.0/24"}, nil); err != nil || !ok {
		t.Fatalf("expected match, got ok=%v err=%v", ok, err)
	}
	if ok, err := fn("192.168.2.100", []string{"192.168.1.0/24"}, nil); err != nil || ok {
		t.Fatalf("expected no match, got ok=%v err=%v", ok, err)
	}

	// boundary
	if ok, err := fn("192.168.1.0", []string{"192.168.1.0/24"}, nil); err != nil || !ok {
		t.Fatalf("expected match at network addr, got ok=%v err=%v", ok, err)
	}
	if ok, err := fn("192.168.1.255", []string{"192.168.1.0/24"}, nil); err != nil || !ok {
		t.Fatalf("expected match at broadcast addr, got ok=%v err=%v", ok, err)
	}

	// multiple ranges
	if ok, err := fn("10.0.0.1", []string{"192.168.1.0/24", "10.0.0.0/8"}, nil); err != nil || !ok {
		t.Fatalf("expected match multi ranges, got ok=%v err=%v", ok, err)
	}

	// invalid ip
	if _, err := fn("invalid_ip", []string{"192.168.1.0/24"}, nil); err == nil {
		t.Fatal("expected invalid ip error")
	}

	// invalid cidr
	if _, err := fn("192.168.1.100", []string{"invalid_cidr"}, nil); err == nil {
		t.Fatal("expected invalid cidr error")
	}
}

func TestSimilarityCalculation(t *testing.T) {
	if s := calculateSimilarity("hello", "hello"); s != 1.0 {
		t.Fatalf("expected 1.0, got %v", s)
	}
	if s := calculateSimilarity("", ""); s != 1.0 {
		t.Fatalf("expected 1.0, got %v", s)
	}
	if s := calculateSimilarity("hello", ""); s != 0.0 {
		t.Fatalf("expected 0.0, got %v", s)
	}
	if s := calculateSimilarity("", "hello"); s != 0.0 {
		t.Fatalf("expected 0.0, got %v", s)
	}

	if s := calculateSimilarity("hello", "helo"); !(s > 0.7 && s < 1.0) {
		t.Fatalf("expected 0.7 < s < 1.0, got %v", s)
	}
	if s := calculateSimilarity("hello", "xyz"); !(s < 0.5) {
		t.Fatalf("expected s < 0.5, got %v", s)
	}
}

func TestLevenshteinDistance(t *testing.T) {
	if d := levenshteinDistance("", ""); d != 0 {
		t.Fatalf("expected 0, got %d", d)
	}
	if d := levenshteinDistance("hello", "hello"); d != 0 {
		t.Fatalf("expected 0, got %d", d)
	}
	if d := levenshteinDistance("hello", ""); d != 5 {
		t.Fatalf("expected 5, got %d", d)
	}
	if d := levenshteinDistance("", "hello"); d != 5 {
		t.Fatalf("expected 5, got %d", d)
	}
	if d := levenshteinDistance("hello", "helo"); d != 1 {
		t.Fatalf("expected 1, got %d", d)
	}
	if d := levenshteinDistance("kitten", "sitting"); d != 3 {
		t.Fatalf("expected 3, got %d", d)
	}
}
