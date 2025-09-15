package compiler

import (
	"testing"

	engine "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

func makeSelMap() map[string][]engine.PrimitiveId {
	return map[string][]engine.PrimitiveId{
		"selection1": {0},
		"selection2": {1},
		"selection3": {2},
	}
}

func TestTokenizeSimpleIdentifier(t *testing.T) {
	toks, err := TokenizeCondition("selection1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(toks) != 1 || toks[0].Kind != TokIdentifier || toks[0].Text != "selection1" {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestTokenizeAndExpression(t *testing.T) {
	toks, err := TokenizeCondition("selection1 and selection2")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(toks) != 3 || toks[1].Kind != TokAnd {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestTokenizeOrExpression(t *testing.T) {
	toks, err := TokenizeCondition("selection1 or selection2")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(toks) != 3 || toks[1].Kind != TokOr {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestTokenizeNotExpression(t *testing.T) {
	toks, err := TokenizeCondition("not selection1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(toks) != 2 || toks[0].Kind != TokNot || toks[1].Kind != TokIdentifier {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestTokenizeParentheses(t *testing.T) {
	toks, err := TokenizeCondition("(selection1 and selection2)")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(toks) != 5 || toks[0].Kind != TokLeftParen || toks[4].Kind != TokRightParen {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestTokenizeNumbers(t *testing.T) {
	toks, err := TokenizeCondition("2 of selection*")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(toks) != 3 || toks[0].Kind != TokNumber || toks[1].Kind != TokOf || toks[2].Kind != TokWildcard {
		t.Fatalf("bad tokens: %#v", toks)
	}
	if toks[0].Number != 2 {
		t.Fatalf("num = %d", toks[0].Number)
	}
}

func TestTokenizeWildcard(t *testing.T) {
	toks, err := TokenizeCondition("selection*")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(toks) != 1 || toks[0].Kind != TokWildcard || toks[0].Text != "selection*" {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestTokenizeAllOfThem(t *testing.T) {
	toks, err := TokenizeCondition("all of them")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(toks) != 3 || toks[0].Kind != TokAll || toks[1].Kind != TokOf || toks[2].Kind != TokThem {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestTokenizeOneOfThem(t *testing.T) {
	toks, err := TokenizeCondition("1 of them")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !(len(toks) == 3 && toks[0].Kind == TokNumber && toks[0].Number == 1 && toks[1].Kind == TokOf && toks[2].Kind == TokThem) {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestTokenizeInvalidCharacter(t *testing.T) {
	_, err := TokenizeCondition("selection1 @ selection2")
	if err == nil || err.Error() == "" {
		t.Fatalf("expected error for invalid character")
	}
}

func TestTokenizeWhitespaceHandling(t *testing.T) {
	toks, err := TokenizeCondition("  selection1   and   selection2  ")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(toks) != 3 {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestParseSimpleIdentifier(t *testing.T) {
	toks := []Token{{Kind: TokIdentifier, Text: "selection1"}}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !(ast.Kind == AstIdentifier && ast.Name == "selection1") {
		t.Fatalf("bad ast: %#v", ast)
	}
}

func TestParseAndExpression(t *testing.T) {
	toks := []Token{
		{Kind: TokIdentifier, Text: "selection1"},
		{Kind: TokAnd},
		{Kind: TokIdentifier, Text: "selection2"},
	}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ast.Kind != AstOr && ast.Kind != AstAnd {
		// tối thiểu phải là And
	}
	if ast.Kind != AstAnd {
		t.Fatalf("want AND at top or nested; got %#v", ast)
	}
}

func TestParseOrExpression(t *testing.T) {
	toks := []Token{
		{Kind: TokIdentifier, Text: "selection1"},
		{Kind: TokOr},
		{Kind: TokIdentifier, Text: "selection2"},
	}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ast.Kind != AstOr {
		t.Fatalf("want OR; got %#v", ast)
	}
}

func TestParseNotExpression(t *testing.T) {
	toks := []Token{
		{Kind: TokNot},
		{Kind: TokIdentifier, Text: "selection1"},
	}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ast.Kind != AstNot || ast.Operand == nil {
		t.Fatalf("bad NOT: %#v", ast)
	}
}

func TestParseParentheses(t *testing.T) {
	toks := []Token{
		{Kind: TokLeftParen},
		{Kind: TokIdentifier, Text: "selection1"},
		{Kind: TokAnd},
		{Kind: TokIdentifier, Text: "selection2"},
		{Kind: TokRightParen},
	}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// (sel1 and sel2) -> AND
	if ast.Kind != AstAnd {
		t.Fatalf("want AND; got %#v", ast)
	}
}

func TestParseAllOfThem(t *testing.T) {
	toks := []Token{{Kind: TokAll}, {Kind: TokOf}, {Kind: TokThem}}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ast.Kind != AstAllOfThem {
		t.Fatalf("want AllOfThem; got %#v", ast)
	}
}

func TestParseOneOfThem(t *testing.T) {
	toks := []Token{{Kind: TokNumber, Number: 1}, {Kind: TokOf}, {Kind: TokThem}}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ast.Kind != AstOneOfThem {
		t.Fatalf("want OneOfThem; got %#v", ast)
	}
}

func TestParseCountOfPattern(t *testing.T) {
	toks := []Token{
		{Kind: TokNumber, Number: 2},
		{Kind: TokOf},
		{Kind: TokWildcard, Text: "selection*"},
	}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !(ast.Kind == AstCountOfPattern && ast.Count == 2 && ast.Pattern == "selection*") {
		t.Fatalf("bad CountOfPattern: %#v", ast)
	}
}

func TestParseAllOfPattern(t *testing.T) {
	toks := []Token{{Kind: TokAll}, {Kind: TokOf}, {Kind: TokWildcard, Text: "selection*"}}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !(ast.Kind == AstAllOfPattern && ast.Pattern == "selection*") {
		t.Fatalf("bad AllOfPattern: %#v", ast)
	}
}

func TestParseOneOfPattern(t *testing.T) {
	toks := []Token{{Kind: TokNumber, Number: 1}, {Kind: TokOf}, {Kind: TokWildcard, Text: "selection*"}}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Rust test: "1 of pattern" -> CountOfPattern(1, pattern)
	if !(ast.Kind == AstCountOfPattern && ast.Count == 1 && ast.Pattern == "selection*") {
		t.Fatalf("bad 1-of-pattern: %#v", ast)
	}
}

func TestParseEmptyTokens(t *testing.T) {
	_, err := ParseTokens(nil, makeSelMap())
	if err == nil || err.Error() == "" || (err != nil && !contains(err.Error(), "Empty condition")) {
		t.Fatalf("want Empty condition err, got: %v", err)
	}
}

func TestParseMissingClosingParenthesis(t *testing.T) {
	toks := []Token{
		{Kind: TokLeftParen},
		{Kind: TokIdentifier, Text: "selection1"},
		{Kind: TokAnd},
		{Kind: TokIdentifier, Text: "selection2"},
		// missing RightParen
	}
	_, err := ParseTokens(toks, makeSelMap())
	if err == nil || !contains(err.Error(), "Expected closing parenthesis") {
		t.Fatalf("want closing paren err, got: %v", err)
	}
}

func TestParseInvalidAfterAll(t *testing.T) {
	toks := []Token{{Kind: TokAll}, {Kind: TokIdentifier, Text: "invalid"}}
	_, err := ParseTokens(toks, makeSelMap())
	if err == nil || !contains(err.Error(), "Expected 'of' after 'all'") {
		t.Fatalf("want err for 'all' without 'of': %v", err)
	}
}

func TestParseInvalidAfterOf(t *testing.T) {
	toks := []Token{{Kind: TokAll}, {Kind: TokOf}, {Kind: TokIdentifier, Text: "invalid"}}
	_, err := ParseTokens(toks, makeSelMap())
	if err == nil || !contains(err.Error(), "Expected 'them' or pattern after 'of'") {
		t.Fatalf("want err after 'of': %v", err)
	}
}

func TestParseUnexpectedToken(t *testing.T) {
	toks := []Token{{Kind: TokRightParen}}
	_, err := ParseTokens(toks, makeSelMap())
	if err == nil || !contains(err.Error(), "Unexpected token in condition") {
		t.Fatalf("want unexpected token err, got: %v", err)
	}
}

func TestParseComplexExpression(t *testing.T) {
	// (selection1 and selection2) or not selection3
	toks := []Token{
		{Kind: TokLeftParen},
		{Kind: TokIdentifier, Text: "selection1"},
		{Kind: TokAnd},
		{Kind: TokIdentifier, Text: "selection2"},
		{Kind: TokRightParen},
		{Kind: TokOr},
		{Kind: TokNot},
		{Kind: TokIdentifier, Text: "selection3"},
	}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ast.Kind != AstOr || ast.Left == nil || ast.Right == nil {
		t.Fatalf("want OR with children; got %#v", ast)
	}
}

func TestParseOperatorPrecedence(t *testing.T) {
	// selection1 and selection2 or selection3
	toks := []Token{
		{Kind: TokIdentifier, Text: "selection1"},
		{Kind: TokAnd},
		{Kind: TokIdentifier, Text: "selection2"},
		{Kind: TokOr},
		{Kind: TokIdentifier, Text: "selection3"},
	}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ast.Kind != AstOr {
		t.Fatalf("top-level should be OR due to precedence; got %#v", ast)
	}
}

func TestParseMultipleNumbers(t *testing.T) {
	toks, err := TokenizeCondition("123 of selection*")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !(len(toks) == 3 && toks[0].Kind == TokNumber && toks[0].Number == 123) {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestParseZeroCount(t *testing.T) {
	toks := []Token{
		{Kind: TokNumber, Number: 0},
		{Kind: TokOf},
		{Kind: TokWildcard, Text: "selection*"},
	}
	ast, err := ParseTokens(toks, makeSelMap())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !(ast.Kind == AstCountOfPattern && ast.Count == 0) {
		t.Fatalf("bad zero CountOfPattern: %#v", ast)
	}
}

func TestTokenizeUnderscoreIdentifiers(t *testing.T) {
	toks, err := TokenizeCondition("_internal_selection")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !(len(toks) == 1 && toks[0].Kind == TokIdentifier && toks[0].Text == "_internal_selection") {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestTokenizeMixedCase(t *testing.T) {
	toks, err := TokenizeCondition("Selection1 AND Selection2")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(toks) != 3 {
		t.Fatalf("bad tokens len: %v", toks)
	}
	// "AND" không phải keyword (case-sensitive), phải là Identifier("AND")
	if !(toks[0].Kind == TokIdentifier && toks[0].Text == "Selection1" &&
		toks[1].Kind == TokIdentifier && toks[1].Text == "AND" &&
		toks[2].Kind == TokIdentifier && toks[2].Text == "Selection2") {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

func TestTokenizeAlphanumericIdentifiers(t *testing.T) {
	toks, err := TokenizeCondition("selection123 and test456")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !(len(toks) == 3 && toks[0].Kind == TokIdentifier && toks[1].Kind == TokAnd && toks[2].Kind == TokIdentifier) {
		t.Fatalf("bad tokens: %#v", toks)
	}
}

// ------------- helpers -------------

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	// simple search
outer:
	for i := 0; i+len(sub) <= len(s); i++ {
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
