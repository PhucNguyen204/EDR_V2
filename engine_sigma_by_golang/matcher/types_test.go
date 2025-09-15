package matcher

import (
	"errors"
	"strings"
	"testing"
)

func TestMatchFnSignature(t *testing.T) {
	exactMatch := MatchFn(func(fieldValue string, values []string, _ []string) (bool, error) {
		for _, v := range values {
			if fieldValue == v {
				return true, nil
			}
		}
		return false, nil
	})

	ok, err := exactMatch("test", []string{"test", "other"}, nil)
	if err != nil || !ok {
		t.Fatalf("want true, got ok=%v err=%v", ok, err)
	}

	ok, err = exactMatch("nomatch", []string{"test", "other"}, nil)
	if err != nil || ok {
		t.Fatalf("want false, got ok=%v err=%v", ok, err)
	}
}

func TestModifierFnSignature(t *testing.T) {
	uppercase := ModifierFn(func(input string) (string, error) {
		return strings.ToUpper(input), nil
	})

	out, err := uppercase("hello")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out != "HELLO" {
		t.Fatalf("want HELLO, got %q", out)
	}
}

func TestModifierFnError(t *testing.T) {
	failing := ModifierFn(func(string) (string, error) {
		return "", errors.New("Test error")
	})
	_, err := failing("test")
	if err == nil || err.Error() != "Test error" {
		t.Fatalf("want Test error, got %v", err)
	}
}

