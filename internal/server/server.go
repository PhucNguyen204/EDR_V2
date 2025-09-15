package server

import (
    "context"
    "database/sql"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strconv"
    "sync"
    "time"

    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
)

type AppServer struct {
    db      *sql.DB
    engine  *dag.DagEngine
    mu      sync.RWMutex // protects engine swap
    evalMu  sync.Mutex   // serialize evaluator usage (not goroutine-safe)
}

func NewAppServer(db *sql.DB, engine *dag.DagEngine) *AppServer {
    return &AppServer{db: db, engine: engine}
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
    type det struct{ ID int64; OccurredAt time.Time; EndpointID string; RuleID int32; RuleName string; Severity string; Confidence float64; Context json.RawMessage }
    out := []det{}
    for rows.Next() {
        var d det
        if err := rows.Scan(&d.ID, &d.OccurredAt, &d.EndpointID, &d.RuleID, &d.RuleName, &d.Severity, &d.Confidence, &d.Context); err != nil { writeErr(w, 500, err); return }
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
        _ = s.insertEvent(r.Context(), ep.EndpointID, ev)
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
    stmts := []string{
        `CREATE TABLE IF NOT EXISTS endpoints (
            endpoint_id   TEXT PRIMARY KEY,
            host_name     TEXT,
            ip            TEXT,
            agent_version TEXT,
            last_seen     TIMESTAMP NOT NULL
        )`,
        `CREATE TABLE IF NOT EXISTS events (
            id          BIGSERIAL PRIMARY KEY,
            received_at TIMESTAMP NOT NULL,
            endpoint_id TEXT,
            event       JSONB
        )`,
        `CREATE TABLE IF NOT EXISTS detections (
            id          BIGSERIAL PRIMARY KEY,
            occurred_at TIMESTAMP NOT NULL,
            endpoint_id TEXT,
            rule_id     INTEGER,
            rule_name   TEXT,
            severity    TEXT,
            confidence  DOUBLE PRECISION,
            context     JSONB
        )`,
    }
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    for _, ssql := range stmts {
        if _, err := s.db.ExecContext(ctx, ssql); err != nil { return err }
    }
    return nil
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

func (s *AppServer) insertEvent(ctx context.Context, endpointID string, ev map[string]any) error {
    b, _ := json.Marshal(ev)
    _, err := s.db.ExecContext(ctx, `INSERT INTO events(received_at, endpoint_id, event) VALUES ($1,$2,$3)`, time.Now().UTC(), endpointID, string(b))
    return err
}

func (s *AppServer) insertDetection(ctx context.Context, endpointID string, ruleID int32, ruleName, severity string, confidence float64, ev map[string]any) error {
    b, _ := json.Marshal(ev)
    _, err := s.db.ExecContext(ctx, `INSERT INTO detections(occurred_at, endpoint_id, rule_id, rule_name, severity, confidence, context) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        time.Now().UTC(), endpointID, ruleID, ruleName, severity, confidence, string(b))
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
