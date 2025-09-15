package matcher

// Advanced matchers ported from Rust advanced.rs with adjustments for Go engine.
//
// - Range matcher supports:
//   • Inclusive ranges:   "10..20"
//   • Exclusive ranges:   "10...20"
//   • Comparisons:        ">10", ">=10", "<20", "<=20"
//   • Exact numeric:      "123" or "3.14"
//   • Back-compat:        "10-20" (hyphen) as in current defaults tests
// - Fuzzy matcher supports threshold modifiers:
//   • "fuzzy:0.9" (Rust style)
//   • "threshold:0.9" (current Go style)

import (
	"fmt"
	"strconv"
	"strings"
)

// ----- Numeric helpers -----

type numericValue struct {
	isFloat bool
	i64     int64
	f64     float64
}

func parseNumericValue(s string) (numericValue, error) {
	// Try integer first for precision
	if iv, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
		return numericValue{isFloat: false, i64: iv, f64: float64(iv)}, nil
	}
	if fv, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		return numericValue{isFloat: true, i64: int64(fv), f64: fv}, nil
	}
	return numericValue{}, fmt.Errorf("InvalidNumericValue: %s", s)
}

// compareNumbers returns -1 if a<b, 0 if a==b, 1 if a>b
func compareNumbers(a, b numericValue) int {
	if !a.isFloat && !b.isFloat {
		if a.i64 < b.i64 {
			return -1
		} else if a.i64 > b.i64 {
			return 1
		}
		return 0
	}
	af := a.f64
	bf := b.f64
	if af < bf {
		return -1
	} else if af > bf {
		return 1
	}
	return 0
}

func isNumberInRange(val numericValue, expr string) (bool, error) {
	e := strings.TrimSpace(expr)

	if strings.Contains(e, "..") {
		// Inclusive or exclusive range using dots
		exclusive := strings.Contains(e, "...")
		var parts []string
		if exclusive {
			parts = strings.SplitN(e, "...", 2)
		} else {
			parts = strings.SplitN(e, "..", 2)
		}
		if len(parts) != 2 {
			return false, fmt.Errorf("InvalidRange: %s", expr)
		}
		lo, err := parseNumericValue(parts[0])
		if err != nil {
			return false, err
		}
		hi, err := parseNumericValue(parts[1])
		if err != nil {
			return false, err
		}
		lowerOK := compareNumbers(val, lo) >= 0
		upperCmp := compareNumbers(val, hi)
		upperOK := upperCmp <= 0
		if exclusive {
			upperOK = upperCmp < 0
		}
		return lowerOK && upperOK, nil
	}

	// Back-compat hyphen ranges like "10-20" (avoid treating negative numbers as ranges)
	if idx := strings.Index(e, "-"); idx > 0 && idx < len(e)-1 {
		// Exclude comparison operators and scientific notation edge-cases by best-effort
		// Only accept single hyphen
		if strings.Count(e, "-") == 1 {
			lo, err := parseNumericValue(e[:idx])
			if err != nil {
				return false, err
			}
			hi, err := parseNumericValue(e[idx+1:])
			if err != nil {
				return false, err
			}
			return compareNumbers(val, lo) >= 0 && compareNumbers(val, hi) <= 0, nil
		}
	}

	// Comparison operators
	if strings.HasPrefix(e, ">=") {
		b, err := parseNumericValue(strings.TrimSpace(strings.TrimPrefix(e, ">=")))
		if err != nil {
			return false, err
		}
		return compareNumbers(val, b) >= 0, nil
	}
	if strings.HasPrefix(e, "<=") {
		b, err := parseNumericValue(strings.TrimSpace(strings.TrimPrefix(e, "<=")))
		if err != nil {
			return false, err
		}
		return compareNumbers(val, b) <= 0, nil
	}
	if strings.HasPrefix(e, ">") {
		b, err := parseNumericValue(strings.TrimSpace(strings.TrimPrefix(e, ">")))
		if err != nil {
			return false, err
		}
		return compareNumbers(val, b) > 0, nil
	}
	if strings.HasPrefix(e, "<") {
		b, err := parseNumericValue(strings.TrimSpace(strings.TrimPrefix(e, "<")))
		if err != nil {
			return false, err
		}
		return compareNumbers(val, b) < 0, nil
	}

	// Exact numeric equality
	b, err := parseNumericValue(e)
	if err != nil {
		return false, err
	}
	return compareNumbers(val, b) == 0, nil
}

// ----- Advanced MatchFns -----

func createAdvancedRangeMatch() MatchFn {
	return func(fieldValue string, values []string, _ []string) (bool, error) {
		v, err := parseNumericValue(fieldValue)
		if err != nil {
			return false, err
		}
		for _, r := range values {
			ok, err := isNumberInRange(v, r)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
}

func extractFuzzyThreshold(modifiers []string) (float64, bool) {
	for _, m := range modifiers {
		if strings.HasPrefix(m, "fuzzy:") {
			if t, err := strconv.ParseFloat(strings.TrimPrefix(m, "fuzzy:"), 64); err == nil && t >= 0.0 && t <= 1.0 {
				return t, true
			}
		}
		if strings.HasPrefix(m, "threshold:") {
			if t, err := strconv.ParseFloat(strings.TrimPrefix(m, "threshold:"), 64); err == nil && t >= 0.0 && t <= 1.0 {
				return t, true
			}
		}
	}
	return 0, false
}

func createAdvancedFuzzyMatch() MatchFn {
	return func(fieldValue string, values []string, modifiers []string) (bool, error) {
		thr, ok := extractFuzzyThreshold(modifiers)
		if !ok {
			thr = 0.8
		}
		for _, p := range values {
			if calculateSimilarity(fieldValue, p) >= thr {
				return true, nil
			}
		}
		return false, nil
	}
}

// RegisterAdvancedOverrides replaces default implementations with advanced ones.
// Call this if you want to enable the richer syntax without altering defaults.go.
func RegisterAdvancedOverrides(matchRegistry map[string]MatchFn) {
	if matchRegistry == nil {
		return
	}
	matchRegistry["range"] = createAdvancedRangeMatch()
	matchRegistry["fuzzy"] = createAdvancedFuzzyMatch()
}
