package engine

import (
	"strings"
)

// AC automaton đơn giản cho Unicode (duyệt từng rune)
type acNode struct {
	next map[rune]int // edges
	fail int          // failure link
	out  []int        // danh sách pattern IDs match tại node này
}

type AhoCorasick struct {
	nodes    []acNode
	patterns []string   // pattern gốc (lowercased)
}

// NewAC: build trie + failure links (BFS)
func NewAC(patterns []string) *AhoCorasick {
	ac := &AhoCorasick{nodes: []acNode{{next: map[rune]int{}}}}
	// chèn pattern
	for pid, p := range patterns {
		p = strings.ToLower(p)
		ac.patterns = append(ac.patterns, p)
		cur := 0
		for _, r := range p {
			nxt, ok := ac.nodes[cur].next[r]
			if !ok {
				nxt = len(ac.nodes)
				ac.nodes = append(ac.nodes, acNode{next: map[rune]int{}})
				ac.nodes[cur].next[r] = nxt
			}
			cur = nxt
		}
		ac.nodes[cur].out = append(ac.nodes[cur].out, pid)
	}
	// build fail links
	type qitem struct{ u int }
	q := []qitem{}
	// mức 1: fail = 0
	for r, v := range ac.nodes[0].next {
		_ = r
		ac.nodes[v].fail = 0
		q = append(q, qitem{u: v})
	}
	// BFS
	for h := 0; h < len(q); h++ {
		u := q[h].u
		for r, v := range ac.nodes[u].next {
			q = append(q, qitem{u: v})
			// tìm fail cho v
			f := ac.nodes[u].fail
			for {
				if to, ok := ac.nodes[f].next[r]; ok {
					ac.nodes[v].fail = to
					break
				}
				if f == 0 {
					ac.nodes[v].fail = 0
					break
				}
				f = ac.nodes[f].fail
			}
			// cộng dồn output
			ac.nodes[v].out = append(ac.nodes[v].out, ac.nodes[ac.nodes[v].fail].out...)
		}
	}
	return ac
}

// FindAny: trả về tập pattern IDs xuất hiện trong text (lowercased, case-insensitive)
func (ac *AhoCorasick) FindAny(text string) map[int]struct{} {
	res := map[int]struct{}{}
	cur := 0
	for _, r := range strings.ToLower(text) {
		for {
			if to, ok := ac.nodes[cur].next[r]; ok {
				cur = to
				break
			}
			if cur == 0 {
				break
			}
			cur = ac.nodes[cur].fail
		}
		for _, pid := range ac.nodes[cur].out {
			res[pid] = struct{}{}
		}
	}
	return res
}
