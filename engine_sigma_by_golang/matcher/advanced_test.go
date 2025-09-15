package matcher

import "testing"

func TestAdvancedRangeMatching(t *testing.T) {
    fn := createAdvancedRangeMatch()

    if ok, err := fn("15", []string{"10..20"}, nil); err != nil || !ok {
        t.Fatalf("expected true for 15 in 10..20, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("25", []string{"10..20"}, nil); err != nil || ok {
        t.Fatalf("expected false for 25 in 10..20, got ok=%v err=%v", ok, err)
    }

    if ok, err := fn("15", []string{">10"}, nil); err != nil || !ok {
        t.Fatalf("expected true for 15 > 10, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("5", []string{">10"}, nil); err != nil || ok {
        t.Fatalf("expected false for 5 > 10, got ok=%v err=%v", ok, err)
    }

    if ok, err := fn("15.5", []string{"10.0..20.0"}, nil); err != nil || !ok {
        t.Fatalf("expected true for 15.5 in 10.0..20.0, got ok=%v err=%v", ok, err)
    }
}

func TestAdvancedFuzzyMatching(t *testing.T) {
    fn := createAdvancedFuzzyMatch()

    if ok, err := fn("hello", []string{"hello"}, nil); err != nil || !ok {
        t.Fatalf("expected exact match true, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("hello", []string{"helo"}, []string{"fuzzy:0.7"}); err != nil || !ok {
        t.Fatalf("expected fuzzy match true, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("hello", []string{"world"}, []string{"fuzzy:0.9"}); err != nil || ok {
        t.Fatalf("expected fuzzy mismatch false, got ok=%v err=%v", ok, err)
    }
}

func TestAdvancedCIDRMatching(t *testing.T) {
    fn := createCIDRMatch()

    if ok, err := fn("192.168.1.100", []string{"192.168.1.0/24"}, nil); err != nil || !ok {
        t.Fatalf("expected ipv4 match, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("10.0.0.1", []string{"192.168.1.0/24"}, nil); err != nil || ok {
        t.Fatalf("expected ipv4 mismatch, got ok=%v err=%v", ok, err)
    }

    if ok, err := fn("2001:db8::1", []string{"2001:db8::/32"}, nil); err != nil || !ok {
        t.Fatalf("expected ipv6 match, got ok=%v err=%v", ok, err)
    }
}

func TestAdvancedRangeMatchingComprehensive(t *testing.T) {
    fn := createAdvancedRangeMatch()

    // boundaries inclusive
    for _, v := range []string{"10", "20"} {
        if ok, err := fn(v, []string{"10..20"}, nil); err != nil || !ok {
            t.Fatalf("expected boundary true for %s in 10..20, got ok=%v err=%v", v, ok, err)
        }
    }
    for _, v := range []string{"9", "21"} {
        if ok, err := fn(v, []string{"10..20"}, nil); err != nil || ok {
            t.Fatalf("expected outside false for %s in 10..20, got ok=%v err=%v", v, ok, err)
        }
    }

    if ok, err := fn("15", []string{">=10"}, nil); err != nil || !ok {
        t.Fatalf("expected 15 >= 10 true, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("10", []string{">=10"}, nil); err != nil || !ok {
        t.Fatalf("expected 10 >= 10 true, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("9", []string{">=10"}, nil); err != nil || ok {
        t.Fatalf("expected 9 >= 10 false, got ok=%v err=%v", ok, err)
    }

    if ok, err := fn("5", []string{"<=10"}, nil); err != nil || !ok {
        t.Fatalf("expected 5 <= 10 true, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("10", []string{"<=10"}, nil); err != nil || !ok {
        t.Fatalf("expected 10 <= 10 true, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("11", []string{"<=10"}, nil); err != nil || ok {
        t.Fatalf("expected 11 <= 10 false, got ok=%v err=%v", ok, err)
    }

    if ok, err := fn("-5", []string{"-10..0"}, nil); err != nil || !ok {
        t.Fatalf("expected -5 in -10..0 true, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("5", []string{"-10..0"}, nil); err != nil || ok {
        t.Fatalf("expected 5 in -10..0 false, got ok=%v err=%v", ok, err)
    }
}

func TestAdvancedFuzzyMatchingComprehensive(t *testing.T) {
    fn := createAdvancedFuzzyMatch()

    if ok, err := fn("hello", []string{"helo"}, []string{"fuzzy:0.5"}); err != nil || !ok {
        t.Fatalf("expected true for fuzzy 0.5, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("hello", []string{"xyz"}, []string{"fuzzy:0.9"}); err != nil || ok {
        t.Fatalf("expected false for xyz fuzzy 0.9, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("", []string{""}, nil); err != nil || !ok {
        t.Fatalf("expected empty match true, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("hello", []string{""}, []string{"fuzzy:0.5"}); err != nil || ok {
        t.Fatalf("expected empty pattern false, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("Hello", []string{"hello"}, []string{"fuzzy:0.8"}); err != nil || !ok {
        t.Fatalf("expected case-insensitive-ish 0.8 true, got ok=%v err=%v", ok, err)
    }
}

func TestAdvancedCIDRMatchingComprehensive(t *testing.T) {
    fn := createCIDRMatch()

    if ok, err := fn("127.0.0.1", []string{"127.0.0.0/8"}, nil); err != nil || !ok {
        t.Fatalf("expected loopback /8 true, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("192.168.1.1", []string{"192.168.0.0/16"}, nil); err != nil || !ok {
        t.Fatalf("expected 192.168/16 true, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("192.169.1.1", []string{"192.168.0.0/16"}, nil); err != nil || ok {
        t.Fatalf("expected 192.169 outside false, got ok=%v err=%v", ok, err)
    }

    if ok, err := fn("::1", []string{"::/0"}, nil); err != nil || !ok {
        t.Fatalf("expected ::/0 true, got ok=%v err=%v", ok, err)
    }
    if ok, err := fn("fe80::1", []string{"fe80::/10"}, nil); err != nil || !ok {
        t.Fatalf("expected fe80::/10 true, got ok=%v err=%v", ok, err)
    }

    if _, err := fn("invalid_ip", []string{"192.168.1.0/24"}, nil); err == nil {
        t.Fatalf("expected error for invalid ip")
    }
    if _, err := fn("192.168.1.1", []string{"invalid_cidr"}, nil); err == nil {
        t.Fatalf("expected error for invalid cidr")
    }
}

func TestAdvancedMatchersErrorHandling(t *testing.T) {
    rangeFn := createAdvancedRangeMatch()
    if _, err := rangeFn("5", []string{"invalid_range"}, nil); err == nil {
        t.Fatalf("expected error for invalid range string")
    }
    if _, err := rangeFn("not_a_number", []string{"1..10"}, nil); err == nil {
        t.Fatalf("expected error for invalid numeric field value")
    }

    fuzzyFn := createAdvancedFuzzyMatch()
    _ = func() bool { _, _ = fuzzyFn("hello", []string{"hello"}, []string{"fuzzy:invalid"}); return true }()
    _ = func() bool { _, _ = fuzzyFn("hello", []string{"hello"}, []string{"fuzzy:1.5"}); return true }()
}

