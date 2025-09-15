package server

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "strconv"
    "sync"
    "time"

    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
    ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

type AppServer struct {
    db      *sql.DB
    engine  *dag.DagEngine
    mu      sync.RWMutex // protects engine swap
    evalMu  sync.Mutex   // serialize evaluator usage (not goroutine-safe)
    ruleMeta map[uint32]RuleMeta // metadata by numeric RuleId
}

func NewAppServer(db *sql.DB, engine *dag.DagEngine) *AppServer {
    return &AppServer{db: db, engine: engine, ruleMeta: make(map[uint32]RuleMeta)}
}

type RuleMeta struct {
    UID   string
    Title string
    Level string
    Desc  string
}

// RegisterRoutes wires HTTP handlers.
func (s *AppServer) RegisterRoutes(mux *http.ServeMux) {
    mux.HandleFunc("/healthz", s.handleHealth)
    mux.HandleFunc("/api/v1/stats", s.handleStats)
    mux.HandleFunc("/api/v1/endpoints", s.handleListEndpoints)
    mux.HandleFunc("/api/v1/detections", s.handleListDetections)
    mux.HandleFunc("/api/v1/ingest", s.handleIngest)
    mux.HandleFunc("/api/v1/rules", s.handleRules)
}

func (s *AppServer) currentEngine() *dag.DagEngine {
    s.mu.RLock(); defer s.mu.RUnlock()
    return s.engine
}

func (s *AppServer) swapEngine(e *dag.DagEngine) {
    s.mu.Lock(); s.engine = e; s.mu.Unlock()
}

// SetRuleMetaFromRuleset populates in-memory metadata map from compiled ruleset
func (s *AppServer) SetRuleMetaFromRuleset(rs *ir.CompiledRuleset) {
    m := make(map[uint32]RuleMeta, len(rs.Rules))
    for _, r := range rs.Rules {
        m[uint32(r.RuleId)] = RuleMeta{
            UID:   r.RuleUID,
            Title: r.Title,
            Level: r.Level,
            Desc:  r.Description,
        }
    }
    s.mu.Lock()
    s.ruleMeta = m
    s.mu.Unlock()
}

// ---- Handlers ----

func (s *AppServer) handleHealth(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *AppServer) handleStats(w http.ResponseWriter, r *http.Request) {
    type statsResp struct {
        NodesEvaluated       int `json:"nodes_evaluated"`
        PrimitiveEvaluations int `json:"primitive_evaluations"`
        PrefilterHits        int `json:"prefilter_hits"`
        PrefilterMisses      int `json:"prefilter_misses"`
        RuleCount            int `json:"rule_count"`
        NodeCount            int `json:"node_count"`
    }
    eng := s.currentEngine()
    ne, pe, ph, pm := eng.Stats()
    resp := statsResp{
        NodesEvaluated: ne, PrimitiveEvaluations: pe,
        PrefilterHits: ph, PrefilterMisses: pm,
        RuleCount: eng.RuleCount(), NodeCount: eng.NodeCount(),
    }
    writeJSON(w, http.StatusOK, resp)
}

func (s *AppServer) handleListEndpoints(w http.ResponseWriter, r *http.Request) {
    rows, err := s.db.QueryContext(r.Context(), `SELECT endpoint_id, host_name, ip, agent_version, last_seen FROM endpoints ORDER BY last_seen DESC LIMIT 200`)
    if err != nil { writeErr(w, http.StatusInternalServerError, err); return }
    defer rows.Close()
    type ep struct{ EndpointID, HostName, IP, AgentVersion string; LastSeen time.Time }
    out := []ep{}
    for rows.Next() {
        var e ep
        if err := rows.Scan(&e.EndpointID, &e.HostName, &e.IP, &e.AgentVersion, &e.LastSeen); err != nil { writeErr(w, 500, err); return }
        out = append(out, e)
    }
    writeJSON(w, http.StatusOK, out)
}

func (s *AppServer) handleListDetections(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()
    limit := 200
    if v := q.Get("limit"); v != "" { if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 { limit = n } }

    rows, err := s.db.QueryContext(r.Context(), `SELECT id, occurred_at, endpoint_id, rule_id, rule_name, severity, confidence, context FROM detections ORDER BY id DESC LIMIT $1`, limit)
    if err != nil { writeErr(w, 500, err); return }
    defer rows.Close()
    type det struct{
        ID int64 `json:"id"`
        OccurredAt time.Time `json:"occurred_at"`
        EndpointID string `json:"endpoint_id"`
        RuleID int32 `json:"rule_id"`
        RuleName string `json:"rule_name"`
        Severity string `json:"severity"`
        Confidence float64 `json:"confidence"`
        Context json.RawMessage `json:"context"`
        // Enriched from engine metadata
        RuleUID string `json:"rule_uid,omitempty"`
        RuleTitle string `json:"rule_title,omitempty"`
        RuleLevel string `json:"rule_level,omitempty"`
        RuleDescription string `json:"rule_description,omitempty"`
    }
    out := []det{}
    for rows.Next() {
        var d det
        if err := rows.Scan(&d.ID, &d.OccurredAt, &d.EndpointID, &d.RuleID, &d.RuleName, &d.Severity, &d.Confidence, &d.Context); err != nil { writeErr(w, 500, err); return }
        // enrich
        s.mu.RLock()
        if meta, ok := s.ruleMeta[uint32(d.RuleID)]; ok {
            d.RuleUID = meta.UID
            if d.RuleName == "" { d.RuleTitle = meta.Title } else { d.RuleTitle = d.RuleName }
            if d.Severity == "" { d.RuleLevel = meta.Level } else { d.RuleLevel = d.Severity }
            d.RuleDescription = meta.Desc
        }
        s.mu.RUnlock()
        out = append(out, d)
    }
    writeJSON(w, http.StatusOK, out)
}

// handleIngest accepts a JSON object or array of objects.
func (s *AppServer) handleIngest(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost { w.WriteHeader(http.StatusMethodNotAllowed); return }
    dec := json.NewDecoder(r.Body)
    dec.UseNumber()
    var payload any
    if err := dec.Decode(&payload); err != nil { writeErr(w, 400, fmt.Errorf("invalid JSON: %w", err)); return }

    // Normalize to slice
    var events []map[string]any
    switch t := payload.(type) {
    case map[string]any:
        events = []map[string]any{t}
    case []any:
        events = make([]map[string]any, 0, len(t))
        for _, it := range t {
            if m, ok := it.(map[string]any); ok { events = append(events, m) }
        }
    default:
        writeErr(w, 400, fmt.Errorf("payload must be object or array of objects")); return
    }

    eng := s.currentEngine()
    for _, ev := range events {
        // Track endpoint
        ep := extractEndpoint(ev)
        if ep.EndpointID != "" { _ = s.upsertEndpoint(r.Context(), ep) }
        // Store raw event (optional)
        eventID, _ := s.insertEvent(r.Context(), ep.EndpointID, ev)
        // Evaluate
        s.evalMu.Lock()
        res, err := eng.Evaluate(ev)
        s.evalMu.Unlock()
        if err != nil { log.Printf("evaluate error: %v", err); continue }
        if len(res.MatchedRules) > 0 {
            // Console log anomaly
            log.Printf("ALERT endpoint=%s rules=%v nodes=%d prims=%d", ep.EndpointID, res.MatchedRules, res.NodesEvaluated, res.PrimitiveEvaluations)
            // Persist detections per matched rule
            for _, rid := range res.MatchedRules {
                _ = s.insertDetection(r.Context(), ep.EndpointID, int32(rid), "", "medium", 0.7, ev)
                // Also persist event_rules link if we have metadata UID
                s.mu.RLock()
                meta, ok := s.ruleMeta[uint32(rid)]
                s.mu.RUnlock()
                if ok && meta.UID != "" && eventID > 0 {
                    _ = s.insertEventRule(r.Context(), eventID, meta.UID)
                }
            }
        }
    }
    writeJSON(w, http.StatusOK, map[string]any{"ingested": len(events)})
}

// handleRules supports GET (list current counts) and POST (replace rules).
// POST body: { rules: ["yaml...", "yaml..."] }
func (s *AppServer) handleRules(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        eng := s.currentEngine()
        writeJSON(w, http.StatusOK, map[string]any{"rules": eng.RuleCount(), "nodes": eng.NodeCount()})
        return
    case http.MethodPost:
        var req struct{ Rules []string `json:"rules"` }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeErr(w, 400, err); return }
        comp := compiler.New()
        rs, err := comp.CompileRuleset(req.Rules)
        if err != nil { writeErr(w, 400, err); return }
        // update metadata map
        s.SetRuleMetaFromRuleset(rs)
        // upsert rules metadata into DB
        if err := s.UpsertRules(r.Context(), rs); err != nil { writeErr(w, 500, err); return }
        newEngine, err := dag.FromRuleset(rs, dag.DefaultEngineConfig())
        if err != nil { writeErr(w, 500, err); return }
        s.swapEngine(newEngine)
        writeJSON(w, http.StatusOK, map[string]any{"status":"ok","rules": newEngine.RuleCount()})
        return
    default:
        w.WriteHeader(http.StatusMethodNotAllowed)
        return
    }
}

// ---- Persistence ----

func (s *AppServer) InitSchema() error {
    // Use MIGRATIONS_PATH if provided, otherwise try common defaults
    candidates := []string{}
    if mp := os.Getenv("MIGRATIONS_PATH"); mp != "" {
        candidates = append(candidates, mp)
    }
    candidates = append(candidates, "./migrations", "/srv/migrations")
    var lastErr error
    for _, p := range candidates {
        if _, statErr := os.Stat(p); statErr != nil {
            lastErr = statErr
            continue
        }
        if err := s.RunMigrations(p); err != nil {
            lastErr = err
            continue
        }
        return nil
    }
    return fmt.Errorf("init schema: no usable migrations path; last error: %v", lastErr)
}

type endpointRec struct {
    EndpointID, HostName, IP, AgentVersion string
    LastSeen time.Time
}

func (s *AppServer) upsertEndpoint(ctx context.Context, e endpointRec) error {
    _, err := s.db.ExecContext(ctx, `INSERT INTO endpoints(endpoint_id, host_name, ip, agent_version, last_seen)
        VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (endpoint_id) DO UPDATE SET host_name=EXCLUDED.host_name, ip=EXCLUDED.ip, agent_version=EXCLUDED.agent_version, last_seen=EXCLUDED.last_seen`,
        e.EndpointID, e.HostName, e.IP, e.AgentVersion, e.LastSeen,
    )
    return err
}

func (s *AppServer) insertEvent(ctx context.Context, endpointID string, ev map[string]any) (int64, error) {
    b, _ := json.Marshal(ev)
    var id int64
    err := s.db.QueryRowContext(ctx, `INSERT INTO events(received_at, endpoint_id, event) VALUES ($1,$2,$3) RETURNING id`, time.Now().UTC(), endpointID, string(b)).Scan(&id)
    return id, err
}

func (s *AppServer) insertDetection(ctx context.Context, endpointID string, ruleID int32, ruleName, severity string, confidence float64, ev map[string]any) error {
    b, _ := json.Marshal(ev)
    _, err := s.db.ExecContext(ctx, `INSERT INTO detections(occurred_at, endpoint_id, rule_id, rule_name, severity, confidence, context) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        time.Now().UTC(), endpointID, ruleID, ruleName, severity, confidence, string(b))
    return err
}

func (s *AppServer) insertEventRule(ctx context.Context, eventID int64, ruleUID string) error {
    // Insert into event_rules by resolving rules.id via rule_uid
    _, err := s.db.ExecContext(ctx, `INSERT INTO event_rules(event_id, rule_id)
        SELECT $1, id FROM rules WHERE rule_uid=$2
        ON CONFLICT(event_id, rule_id) DO NOTHING`, eventID, ruleUID)
    return err
}

// ---- Helpers ----

func extractEndpoint(ev map[string]any) endpointRec {
    e := endpointRec{LastSeen: time.Now().UTC()}
    // Try different common fields as sent by agents
    if v, ok := ev["endpoint_id"]; ok { e.EndpointID = toString(v) }
    if e.EndpointID == "" { if v, ok := ev["agent.id"]; ok { e.EndpointID = toString(v) } }
    if e.EndpointID == "" { if v, ok := ev["agent_id"]; ok { e.EndpointID = toString(v) } }
    if hn, ok := ev["host"]; ok { if m, ok := hn.(map[string]any); ok { if x, ok := m["name"]; ok { e.HostName = toString(x) } } }
    if e.HostName == "" { if v, ok := ev["host.name"]; ok { e.HostName = toString(v) } }
    if e.HostName == "" { if v, ok := ev["hostname"]; ok { e.HostName = toString(v) } }
    if v, ok := ev["ip"]; ok { e.IP = toString(v) }
    if v, ok := ev["agent.version"]; ok { e.AgentVersion = toString(v) }
    if v, ok := ev["agent_version"]; ok && e.AgentVersion == "" { e.AgentVersion = toString(v) }
    return e
}

func toString(v any) string {
    switch t := v.(type) {
    case string:
        return t
    case json.Number:
        return t.String()
    case float64:
        return strconv.FormatFloat(t, 'g', -1, 64)
    case int, int32, int64:
        return fmt.Sprintf("%v", t)
    case bool:
        if t { return "true" }; return "false"
    default:
        b, _ := json.Marshal(t)
        return string(b)
    }
}

func writeJSON(w http.ResponseWriter, code int, v any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    if err := json.NewEncoder(w).Encode(v); err != nil {
        log.Printf("writeJSON error: %v", err)
    }
}

func writeErr(w http.ResponseWriter, code int, err error) {
    writeJSON(w, code, map[string]any{"error": err.Error()})
}
