//go:build !aho
// +build !aho

package dag

import (
    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// PrefilterStats (stub): mirrors the aho build type with zero values.
type PrefilterStats struct {
    PatternCount         int
    FieldCount           int
    PrimitiveCount       int
    EstimatedSelectivity float64
    MemoryUsage          int
}

// Prefilter is the minimal interface used by evaluator (stub variant).
type Prefilter interface {
    MatchesJSON(any) bool
    MatchesRaw(string) bool
    Stats() PrefilterStats
}

// LiteralPrefilter is a no-op stub when aho build tag is not set.
type LiteralPrefilter struct{}

func (p *LiteralPrefilter) MatchesJSON(_ any) bool { return true }
func (p *LiteralPrefilter) MatchesRaw(_ string) bool { return true }
func (p *LiteralPrefilter) Stats() PrefilterStats    { return PrefilterStats{} }

// PrefilterFromPrimitives returns a stub prefilter in no-aho builds.
func PrefilterFromPrimitives(_ []ir.Primitive) LiteralPrefilter { return LiteralPrefilter{} }
