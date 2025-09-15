package server

import (
    "bytes"
    "database/sql"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    sqlmock "github.com/DATA-DOG/go-sqlmock"

    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
)

// helper to create a tiny engine that matches cmd.exe + whoami
func makeTestEngine(t *testing.T) *dag.DagEngine {
    t.Helper()
    fm := compiler.NewFieldMapping()
    fm.AddMapping("ProcessImage", "Image")
    fm.AddMapping("ProcessCommandLine", "CommandLine")
    c := compiler.WithFieldMapping(fm)
    // Map fields used in rule to runtime fields
    // Our compiler already defaults to normalizing during compile via FieldMapping if configured in rules; here we keep names consistent
    rule := `
title: Whoami Via CMD
detection:
  selection_image:
    ProcessImage|endswith: '\\cmd.exe'
  selection_cmdline:
    ProcessCommandLine|contains: 'whoami'
  condition: selection_image and selection_cmdline
`
    if _, err := c.CompileRule(rule); err != nil {
        t.Fatalf("compile rule: %v", err)
    }
    rs := c.IntoRuleset()
    // Build engine
    eng, err := dag.FromRuleset(rs, dag.DefaultEngineConfig())
    if err != nil { t.Fatalf("build engine: %v", err) }
    return eng
}

func makeServer(t *testing.T, db *sql.DB, eng *dag.DagEngine) (*AppServer, *http.ServeMux) {
    t.Helper()
    s := NewAppServer(db, eng)
    mux := http.NewServeMux()
    s.RegisterRoutes(mux)
    return s, mux
}

func TestHealthz(t *testing.T) {
    db, _, _ := sqlmock.New()
    defer db.Close()
    eng := makeTestEngine(t)
    _, mux := makeServer(t, db, eng)
    req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
    rr := httptest.NewRecorder()
    mux.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK { t.Fatalf("status=%d", rr.Code) }
}

func TestIngestNonMatching(t *testing.T) {
    db, mock, _ := sqlmock.New()
    defer db.Close()
    eng := makeTestEngine(t)
    _, mux := makeServer(t, db, eng)
    // No need to init schema in test

    // Expect endpoint upsert and event insert
    mock.ExpectExec("INSERT INTO endpoints").WillReturnResult(sqlmock.NewResult(0, 1))
    mock.ExpectExec("INSERT INTO events").WillReturnResult(sqlmock.NewResult(0, 1))

    // Non-matching event: different image / cmdline
    ev := map[string]any{
        "endpoint_id": "host-01",
        "Image": "C\\\\Windows\\\\System32\\\\notepad.exe",
        "CommandLine": "notepad.exe readme.txt",
    }
    body, _ := json.Marshal(ev)
    req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    mux.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
    }
    if err := mock.ExpectationsWereMet(); err != nil { t.Fatalf("db expectations: %v", err) }
}

func TestIngestMatching(t *testing.T) {
    db, mock, _ := sqlmock.New()
    defer db.Close()
    eng := makeTestEngine(t)
    s, mux := makeServer(t, db, eng)
    _ = s // silence linter

    // Expect endpoint upsert, event insert, and detection insert
    mock.ExpectExec("INSERT INTO endpoints").WillReturnResult(sqlmock.NewResult(0, 1))
    mock.ExpectExec("INSERT INTO events").WillReturnResult(sqlmock.NewResult(0, 1))
    mock.ExpectExec("INSERT INTO detections").WillReturnResult(sqlmock.NewResult(0, 1))

    // Matching event (note: compiler normalized Process* to runtime fields; runtime expects Image/CommandLine)
    ev := map[string]any{
        "endpoint_id": "host-01",
        "Image": "C\\\\Windows\\\\System32\\\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
    }
    body, _ := json.Marshal(ev)
    req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    mux.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
    }
    if err := mock.ExpectationsWereMet(); err != nil { t.Fatalf("db expectations: %v", err) }
}

func TestIngestBatchMixed(t *testing.T) {
    db, mock, _ := sqlmock.New()
    defer db.Close()
    eng := makeTestEngine(t)
    _, mux := makeServer(t, db, eng)

    // Expect two upserts and two event inserts; one detection
    mock.ExpectExec("INSERT INTO endpoints").WillReturnResult(sqlmock.NewResult(0, 1))
    mock.ExpectExec("INSERT INTO events").WillReturnResult(sqlmock.NewResult(0, 1))
    mock.ExpectExec("INSERT INTO endpoints").WillReturnResult(sqlmock.NewResult(0, 1))
    mock.ExpectExec("INSERT INTO events").WillReturnResult(sqlmock.NewResult(0, 1))
    mock.ExpectExec("INSERT INTO detections").WillReturnResult(sqlmock.NewResult(0, 1))

    payload := []map[string]any{
        { // non-matching
            "endpoint_id": "host-01",
            "Image": "C\\\\Windows\\\\System32\\\\notepad.exe",
            "CommandLine": "notepad.exe readme.txt",
        },
        { // matching
            "endpoint_id": "host-01",
            "Image": "C\\\\Windows\\\\System32\\\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        },
    }
    body, _ := json.Marshal(payload)
    req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    mux.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
    }
    if err := mock.ExpectationsWereMet(); err != nil { t.Fatalf("db expectations: %v", err) }
}

func TestListEndpoints(t *testing.T) {
    db, mock, _ := sqlmock.New()
    defer db.Close()
    eng := makeTestEngine(t)
    _, mux := makeServer(t, db, eng)

    rows := sqlmock.NewRows([]string{"endpoint_id","host_name","ip","agent_version","last_seen"}).
        AddRow("host-01","host-01","10.0.0.1","0.32.0", time.Now())
    mock.ExpectQuery("SELECT endpoint_id, host_name").WillReturnRows(rows)

    req := httptest.NewRequest(http.MethodGet, "/api/v1/endpoints", nil)
    rr := httptest.NewRecorder()
    mux.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK { t.Fatalf("status=%d", rr.Code) }
    if err := mock.ExpectationsWereMet(); err != nil { t.Fatalf("db expectations: %v", err) }
}

func TestRulesReplace(t *testing.T) {
    db, mock, _ := sqlmock.New()
    defer db.Close()
    eng := makeTestEngine(t)
    _, mux := makeServer(t, db, eng)

    // New rules payload (simple equals on EventID)
    body := []byte(`{"rules":["title: R\ndetection:\n  selection:\n    EventID: 4624\n  condition: selection\n"]}`)
    req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    mux.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
    }
    if err := mock.ExpectationsWereMet(); err != nil { t.Fatalf("db expectations: %v", err) }
}

func TestStats(t *testing.T) {
    db, _, _ := sqlmock.New()
    defer db.Close()
    eng := makeTestEngine(t)
    _, mux := makeServer(t, db, eng)
    req := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
    rr := httptest.NewRecorder()
    mux.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
    }
}
