//go:build !aho
// +build !aho

package dag

import (
    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// Prefilter is the minimal interface used by evaluator.
type Prefilter interface {
    MatchesJSON(any) bool
    MatchesRaw(string) bool
}

// LiteralPrefilter is a no-op stub when aho build tag is not set.
type LiteralPrefilter struct{}

func (p *LiteralPrefilter) MatchesJSON(_ any) bool { return true }
func (p *LiteralPrefilter) MatchesRaw(_ string) bool { return true }

// PrefilterFromPrimitives returns a stub prefilter in no-aho builds.
func PrefilterFromPrimitives(_ []ir.Primitive) LiteralPrefilter { return LiteralPrefilter{} }
