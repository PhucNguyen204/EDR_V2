package compiler

import (
	"fmt"
	"unicode"

	engine "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// ---------------- Tokens ----------------

type TokenKind int

const (
	TokIdentifier TokenKind = iota
	TokAnd
	TokOr
	TokNot
	TokLeftParen
	TokRightParen
	TokOf
	TokThem
	TokAll
	TokNumber
	TokWildcard
)

type Token struct {
	Kind     TokenKind
	Text     string  // cho Identifier / Wildcard
	Number   uint32  // cho Number
}

type TokenSlice = Token // Go string slice giữ chung backing; đủ “zero-alloc-ish”

// ---------------- AST ----------------

type AstKind int

const (
	AstIdentifier AstKind = iota
	AstAnd
	AstOr
	AstNot
	AstOneOfThem
	AstAllOfThem
	AstOneOfPattern   // (giữ cho đủ parity với Rust; parser hiện không phát sinh)
	AstAllOfPattern
	AstCountOfPattern
)

type ConditionAst struct {
	Kind AstKind

	// Identifier
	Name string

	// Binary
	Left, Right *ConditionAst

	// Unary
	Operand *ConditionAst

	// Pattern & Count
	Pattern string
	Count   uint32
}

// ---------------- Parser ----------------

type ConditionParser struct {
	tokens       []Token
	pos          int
	selectionMap map[string][]engine.PrimitiveId
}

func NewConditionParser(tokens []Token, selectionMap map[string][]engine.PrimitiveId) *ConditionParser {
	return &ConditionParser{tokens: tokens, pos: 0, selectionMap: selectionMap}
}

func (p *ConditionParser) current() *Token {
	if p.pos >= 0 && p.pos < len(p.tokens) {
		return &p.tokens[p.pos]
	}
	return nil
}

func (p *ConditionParser) advance() *Token {
	tok := p.current()
	if tok != nil {
		p.pos++
	}
	return tok
}

// OR (thấp nhất)
func (p *ConditionParser) parseOrExpression() (*ConditionAst, error) {
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}
	for {
		if t := p.current(); t != nil && t.Kind == TokOr {
			p.advance()
			right, err := p.parseAndExpression()
			if err != nil {
				return nil, err
			}
			left = &ConditionAst{Kind: AstOr, Left: left, Right: right}
			continue
		}
		break
	}
	return left, nil
}

// AND (trung bình)
func (p *ConditionParser) parseAndExpression() (*ConditionAst, error) {
	left, err := p.parseNotExpression()
	if err != nil {
		return nil, err
	}
	for {
		if t := p.current(); t != nil && t.Kind == TokAnd {
			p.advance()
			right, err := p.parseNotExpression()
			if err != nil {
				return nil, err
			}
			left = &ConditionAst{Kind: AstAnd, Left: left, Right: right}
			continue
		}
		break
	}
	return left, nil
}

// NOT (cao nhất)
func (p *ConditionParser) parseNotExpression() (*ConditionAst, error) {
	if t := p.current(); t != nil && t.Kind == TokNot {
		p.advance()
		operand, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &ConditionAst{Kind: AstNot, Operand: operand}, nil
	}
	return p.parsePrimary()
}

func (p *ConditionParser) parsePrimary() (*ConditionAst, error) {
	t := p.current()
	if t == nil {
		return nil, fmt.Errorf("Unexpected token in condition")
	}

	switch t.Kind {
	case TokLeftParen:
		p.advance()
		expr, err := p.parseOrExpression()
		if err != nil {
			return nil, err
		}
		if r := p.current(); r == nil || r.Kind != TokRightParen {
			return nil, fmt.Errorf("Expected closing parenthesis")
		}
		p.advance()
		return expr, nil

	case TokIdentifier:
		name := t.Text
		p.advance()
		if _, ok := p.selectionMap[name]; ok {
			return &ConditionAst{Kind: AstIdentifier, Name: name}, nil
		}
		return nil, fmt.Errorf("Unknown selection identifier: %s", name)

	case TokNumber:
		count := t.Number
		p.advance()
		if r := p.current(); r == nil || r.Kind != TokOf {
			return nil, fmt.Errorf("Expected 'of' after number")
		}
		p.advance()
		r2 := p.current()
		if r2 == nil {
			return nil, fmt.Errorf("Expected 'them' or pattern after 'of'")
		}
		switch r2.Kind {
		case TokThem:
			p.advance()
			if count == 1 {
				return &ConditionAst{Kind: AstOneOfThem}, nil
			}
			return nil, fmt.Errorf("Only '1 of them' is supported")
		case TokWildcard:
			pattern := r2.Text
			p.advance()
			return &ConditionAst{Kind: AstCountOfPattern, Count: count, Pattern: pattern}, nil
		default:
			return nil, fmt.Errorf("Expected 'them' or pattern after 'of'")
		}

	case TokAll:
		p.advance()
		if r := p.current(); r == nil || r.Kind != TokOf {
			return nil, fmt.Errorf("Expected 'of' after 'all'")
		}
		p.advance()
		r2 := p.current()
		if r2 == nil {
			return nil, fmt.Errorf("Expected 'them' or pattern after 'of'")
		}
		switch r2.Kind {
		case TokThem:
			p.advance()
			return &ConditionAst{Kind: AstAllOfThem}, nil
		case TokWildcard:
			pattern := r2.Text
			p.advance()
			return &ConditionAst{Kind: AstAllOfPattern, Pattern: pattern}, nil
		default:
			return nil, fmt.Errorf("Expected 'them' or pattern after 'of'")
		}

	default:
		return nil, fmt.Errorf("Unexpected token in condition")
	}
}

// ---------------- Tokenizer ----------------

// TokenizeConditionZeroAlloc: quét chuỗi và sinh TokenSlice (thực chất là Token giữ substring).
// Nhận diện keyword **chỉ ở dạng thường**: and/or/not/of/them/all.
// "AND" sẽ bị xem là Identifier("AND") — khớp test Rust.
func TokenizeConditionZeroAlloc(cond string) ([]TokenSlice, error) {
	toks := make([]TokenSlice, 0, 8)
	i := 0
	n := len(cond)

	for i < n {
		ch := rune(cond[i])
		// tiến nhanh rune-by-rune (Go string là UTF-8)
		// nhưng ở đây chỉ cần ASCII + chữ số + '_' + '*'
		switch ch {
		case ' ', '\t', '\n', '\r':
			i++
			continue
		case '(':
			toks = append(toks, TokenSlice{Kind: TokLeftParen})
			i++
			continue
		case ')':
			toks = append(toks, TokenSlice{Kind: TokRightParen})
			i++
			continue
		default:
			switch {
			case ch >= '0' && ch <= '9':
				start := i
				i++
				for i < n {
					c := cond[i]
					if c >= '0' && c <= '9' {
						i++
					} else {
						break
					}
				}
				numStr := cond[start:i]
				var num uint64
				for j := 0; j < len(numStr); j++ {
					num = num*10 + uint64(numStr[j]-'0')
				}
				toks = append(toks, TokenSlice{Kind: TokNumber, Number: uint32(num)})
				continue

			case isAlpha(cond, i) || cond[i] == '_':
				start := i
				i++
				for i < n {
					c := cond[i]
					if isAlphaNum(cond, i) || c == '_' || c == '*' {
						i++
					} else {
						break
					}
				}
				ident := cond[start:i]

				// từ khoá chỉ khi lower-case
				switch ident {
				case "and":
					toks = append(toks, TokenSlice{Kind: TokAnd})
				case "or":
					toks = append(toks, TokenSlice{Kind: TokOr})
				case "not":
					toks = append(toks, TokenSlice{Kind: TokNot})
				case "of":
					toks = append(toks, TokenSlice{Kind: TokOf})
				case "them":
					toks = append(toks, TokenSlice{Kind: TokThem})
				case "all":
					toks = append(toks, TokenSlice{Kind: TokAll})
				default:
					if containsStar(ident) {
						toks = append(toks, TokenSlice{Kind: TokWildcard, Text: ident})
									} else {
						toks = append(toks, TokenSlice{Kind: TokIdentifier, Text: ident})
					}
				}
				continue
			default:
				// ký tự bất ngờ (ví dụ '@')
				return nil, fmt.Errorf("Unexpected character in condition: '%c'", ch)
			}
		}
	}

	return toks, nil
}

func containsStar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '*' {
			return true
		}
	}
	return false
}

func isAlpha(s string, i int) bool {
	r := rune(s[i])
	return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || r >= unicode.MaxASCII && unicode.IsLetter(r)
}
func isAlphaNum(s string, i int) bool {
	r := rune(s[i])
	return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') || r >= unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r))
}

// TokenizeCondition: dùng zero-alloc tokenizer rồi chuyển thành Token “owned”
func TokenizeCondition(cond string) ([]Token, error) {
	slices, err := TokenizeConditionZeroAlloc(cond)
	if err != nil {
		return nil, err
	}
	out := make([]Token, 0, len(slices))
	for _, t := range slices {
		out = append(out, t) // ở Go, copy struct là đủ
	}
	return out, nil
}

// ParseTokens: parse thành AST
func ParseTokens(tokens []Token, selectionMap map[string][]engine.PrimitiveId) (*ConditionAst, error) {
	if len(tokens) == 0 {
		return nil, fmt.Errorf("Empty condition")
	}
	p := NewConditionParser(tokens, selectionMap)
	return p.parseOrExpression()
}
