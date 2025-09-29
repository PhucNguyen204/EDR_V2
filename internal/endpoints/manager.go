package endpoints

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Record describes an endpoint identity and last seen metadata
type Record struct {
	EndpointID   string    `json:"endpoint_id"`
	HostName     string    `json:"host_name"`
	IP           string    `json:"ip"`
	AgentVersion string    `json:"agent_version"`
	LastSeen     time.Time `json:"last_seen"`
}

// Manager keeps endpoint records in-memory with concurrent access protection
type Manager struct {
	mu         sync.RWMutex
	items      map[string]Record
	defaultTTL time.Duration
}

// New creates a new endpoint manager
func New(ttl time.Duration) *Manager {
	return &Manager{items: make(map[string]Record), defaultTTL: ttl}
}

// Upsert inserts or updates an endpoint record
func (m *Manager) Upsert(rec Record) {
	if rec.EndpointID == "" {
		// derive from hostname if needed
		if rec.HostName != "" {
			rec.EndpointID = rec.HostName
		}
	}
	if rec.EndpointID == "" {
		return
	}
	if rec.LastSeen.IsZero() {
		rec.LastSeen = time.Now().UTC()
	}
	m.mu.Lock()
	m.items[rec.EndpointID] = rec
	m.mu.Unlock()
}

// Get returns a record by endpoint id
func (m *Manager) Get(id string) (Record, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.items[id]
	return r, ok
}

// List returns up to limit newest endpoints ordered by LastSeen desc
func (m *Manager) List(limit int) []Record {
	m.mu.RLock()
	out := make([]Record, 0, len(m.items))
	for _, v := range m.items {
		out = append(out, v)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

// Cleanup removes endpoints not seen within ttl (if ttl <=0 uses defaultTTL; if both 0, no-op)
func (m *Manager) Cleanup(ttl time.Duration) int {
	effective := ttl
	if effective <= 0 {
		effective = m.defaultTTL
	}
	if effective <= 0 {
		return 0
	}
	cutoff := time.Now().UTC().Add(-effective)
	removed := 0
	m.mu.Lock()
	for k, v := range m.items {
		if v.LastSeen.Before(cutoff) {
			delete(m.items, k)
			removed++
		}
	}
	m.mu.Unlock()
	return removed
}

// FromMap builds a Record from a generic event map (safe best-effort)
func FromMap(ev map[string]any) Record {
	r := Record{LastSeen: time.Now().UTC()}
	if v, ok := ev["endpoint_id"]; ok {
		r.EndpointID = toString(v)
	}
	if hn, ok := ev["host"]; ok {
		if m, ok := hn.(map[string]any); ok {
			if x, ok2 := m["name"]; ok2 {
				r.HostName = toString(x)
			}
		}
	}
	if r.HostName == "" {
		if v, ok := ev["host.name"]; ok {
			r.HostName = toString(v)
		}
	}
	if v, ok := ev["ip"]; ok {
		r.IP = toString(v)
	}
	if v, ok := ev["agent.version"]; ok {
		r.AgentVersion = toString(v)
	}
	if r.EndpointID == "" && r.HostName != "" {
		r.EndpointID = r.HostName
	}
	return r
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	default:
		return strings.TrimSpace(strings.Trim(strings.ReplaceAll(strings.TrimSpace(fmtAny(t)), "\n", " "), "\""))
	}
}

func fmtAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int:
		return strconvI(int64(t))
	case int32:
		return strconvI(int64(t))
	case int64:
		return strconvI(t)
	case float64:
		return strconvF(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func strconvI(i int64) string             { return fmtS("%d", i) }
func strconvF(f float64) string           { return fmtS("%g", f) }
func fmtS(format string, a ...any) string { return sprintf(format, a...) }

// Small wrappers to avoid importing fmt/strconv in this tiny helper
// (keeps dependencies minimal for endpoints manager)
func sprintf(format string, a ...any) string { return _sprintf(format, a...) }

// delegate to fmt.Sprintf without adding import at top-level to keep file concise
//
//go:linkname _sprintf fmt.Sprintf
func _sprintf(format string, a ...any) string
