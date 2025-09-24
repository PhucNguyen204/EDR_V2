package server

import (
    "fmt"
    "strings"
    "sync"
    "time"

    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

type corrHit struct {
    correlationID uint32
    title         string
    level         string
    groupKey      string
    count         int
}

type valueCountDef struct {
    id       uint32
    name     string
    title    string
    level    string
    rules    []string
    groupBy  []string
    timespan time.Duration
    field    string
    gte      int
}

type vcState struct {
    values    map[string]time.Time // value -> lastSeen
    lastCount int
    lastEmit  time.Time
}

type CorrelationManager struct {
    mu    sync.Mutex
    defs  []valueCountDef
    // rule name -> list of def indexes
    index map[string][]int
    // def index -> groupKey -> state
    state map[int]map[string]*vcState
}

func NewCorrelationManagerFromIR(defs []ir.CompiledCorrelationRule) *CorrelationManager {
    cm := &CorrelationManager{
        defs:  make([]valueCountDef, 0, len(defs)),
        index: make(map[string][]int),
        state: make(map[int]map[string]*vcState),
    }
    for _, d := range defs {
        if !strings.EqualFold(d.Type, "value_count") || d.ValueCount == nil {
            continue
        }
        v := valueCountDef{
            id:       d.CorrelationId,
            name:     d.Name,
            title:    coalesce(d.Title, d.Name),
            level:    d.Level,
            rules:    append([]string(nil), d.Rules...),
            groupBy:  append([]string(nil), d.GroupBy...),
            timespan: d.Timespan,
            field:    d.ValueCount.Field,
            gte:      d.ValueCount.Gte,
        }
        idx := len(cm.defs)
        cm.defs = append(cm.defs, v)
        for _, rn := range v.rules {
            cm.index[rn] = append(cm.index[rn], idx)
        }
    }
    return cm
}

// Observe processes a single event with the list of matched base rule names and returns correlation hits.
func (cm *CorrelationManager) Observe(ev map[string]any, matchedRuleNames []string, now time.Time) []corrHit {
    if cm == nil { return nil }
    cm.mu.Lock()
    defer cm.mu.Unlock()

    hits := make([]corrHit, 0)
    seenDefs := make(map[int]struct{})
    for _, rn := range matchedRuleNames {
        for _, di := range cm.index[rn] {
            if _, ok := seenDefs[di]; ok { continue }
            seenDefs[di] = struct{}{}
            def := cm.defs[di]
            gk := cm.buildGroupKey(ev, def.groupBy)
            if gk == "" { gk = "__global__" }
            if cm.state[di] == nil { cm.state[di] = make(map[string]*vcState) }
            st := cm.state[di][gk]
            if st == nil { st = &vcState{values: make(map[string]time.Time)}; cm.state[di][gk] = st }
            val := getStringField(ev, def.field)
            if val == "" {
                // if field missing, fall back to counting events by synthetic id
                val = fmt.Sprintf("evt-%d", now.UnixNano())
            }
            st.values[val] = now
            // purge expired
            expireBefore := now.Add(-def.timespan)
            for v, ts := range st.values {
                if ts.Before(expireBefore) { delete(st.values, v) }
            }
            cnt := len(st.values)
            // fire on threshold crossing
            if cnt >= def.gte && st.lastCount < def.gte {
                hits = append(hits, corrHit{correlationID: def.id, title: def.title, level: def.level, groupKey: gk, count: cnt})
                st.lastEmit = now
            }
            st.lastCount = cnt
        }
    }
    return hits
}

func (cm *CorrelationManager) buildGroupKey(ev map[string]any, fields []string) string {
    if len(fields) == 0 { return "" }
    parts := make([]string, 0, len(fields))
    for _, f := range fields {
        v := getStringField(ev, f)
        parts = append(parts, v)
    }
    return strings.Join(parts, "|")
}

func coalesce(a, b string) string { if a != "" { return a }; return b }

func getStringField(ev map[string]any, path string) string {
    if path == "" { return "" }
    // direct
    if v, ok := ev[path]; ok { return toString(v) }
    // dotted path
    if strings.Contains(path, ".") {
        cur := any(ev)
        for _, seg := range strings.Split(path, ".") {
            m, ok := cur.(map[string]any)
            if !ok { return "" }
            x, ok := m[seg]
            if !ok { return "" }
            cur = x
        }
        return toString(cur)
    }
    return ""
}

