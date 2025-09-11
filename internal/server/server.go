package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
    "sync/atomic"
    "log"
    "os"

	"github.com/PhucNguyen204/EDR_V2/pkg/engine"
)

type AppServer struct {
    eng *engine.Engine
    totalAccepted uint64
    totalMatched  uint64
    totalRequests uint64
    evalErrors    uint64
}

func NewAppServer(eng *engine.Engine) *AppServer { return &AppServer{eng: eng} }

func (s *AppServer) Router() http.Handler {
    mux := http.NewServeMux()
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
        _, _ = io.WriteString(w, "ok")
    })
    mux.HandleFunc("/ingest", s.handleIngest)
    mux.HandleFunc("/stats", s.handleStats)
    return mux
}

type Event = map[string]any

func (s *AppServer) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := readMaybeGzip(r)
	if err != nil {
		http.Error(w, "bad gzip: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer body.Close()

    evs, err := decodeEvents(body)
    if err != nil {
        http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
        return
    }

	type evalResult struct {
		Index   int      `json:"index"`
		Matched []string `json:"matched"`
	}
    out := make([]evalResult, 0, len(evs))
    total := 0
    for i, ev := range evs {
        ids, err := s.eng.Evaluate(ev)
        if err != nil { // không fail toàn batch
            out = append(out, evalResult{Index: i})
            atomic.AddUint64(&s.evalErrors, 1)
            if os.Getenv("EDR_SERVER_LOG_EVAL_ERR") != "" {
                log.Printf("EVAL_ERR idx=%d err=%v event=%s", i, err, summarizeEvent(ev))
            }
            continue
        }
        out = append(out, evalResult{Index: i, Matched: ids})
        total += len(ids)

        //log debug 
        if len(ids) > 0 {
            log.Printf("DETECT idx=%d rules=%v event=%s", i, ids, summarizeEvent(ev))
        }
    }

    // Update counters
    atomic.AddUint64(&s.totalRequests, 1)
    atomic.AddUint64(&s.totalAccepted, uint64(len(evs)))
    atomic.AddUint64(&s.totalMatched, uint64(total))

    w.Header().Set("Content-Type", "application/json")
    resp := map[string]any{
		"accepted": len(evs),
		"matched":  total,
		"results":  out,
	}
    _ = json.NewEncoder(w).Encode(resp)

    if os.Getenv("EDR_SERVER_LOG_INGEST") != "" {
        log.Printf("/ingest accepted=%d matched=%d errors=%d", len(evs), total, atomic.LoadUint64(&s.evalErrors))
    }
}

func (s *AppServer) handleStats(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet { http.Error(w, "method not allowed", http.StatusMethodNotAllowed); return }
    st := s.eng.Stats()
    out := map[string]any{
        "total_requests": atomic.LoadUint64(&s.totalRequests),
        "total_accepted": atomic.LoadUint64(&s.totalAccepted),
        "total_matched":  atomic.LoadUint64(&s.totalMatched),
        "eval_errors":    atomic.LoadUint64(&s.evalErrors),
        "engine": map[string]any{
            "rules":             st.Rules,
            "rules_no_literals": st.RulesNoLiterals,
            "literal_patterns":  st.LiteralPatterns,
        },
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}

// summarizeEvent tạo chuỗi ngắn gọn từ event để in log
func summarizeEvent(ev map[string]any) string {
    pick := func(keys ...string) string {
        for _, k := range keys {
            if v, ok := ev[k]; ok {
                sv := fmt.Sprint(v)
                if len(sv) > 120 { return sv[:117] + "..." }
                return sv
            }
        }
        return ""
    }
    // ưu tiên cho các trường phổ biến
    if s := pick("CommandLine", "Image", "Message", "Description"); s != "" {
        return s
    }
    // Fallback
    b, _ := json.Marshal(ev)
    sv := string(b)
    if len(sv) > 200 { return sv[:197] + "..." }
    return sv
}

func readMaybeGzip(r *http.Request) (io.ReadCloser, error) {
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Encoding")), "gzip") {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		return gz, nil
	}
	return r.Body, nil
}

func decodeEvents(rd io.Reader) ([]Event, error) {
	// Đọc toàn bộ content vào memory để có thể thử nhiều lần
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(rd); err != nil {
		return nil, err
	}

	// Thử decode như array trước
	var evs []Event
	if err := json.Unmarshal(buf.Bytes(), &evs); err == nil {
		return evs, nil
	}

	// Nếu không được, thử decode như single object
	var ev Event
	if err := json.Unmarshal(buf.Bytes(), &ev); err != nil {
		return nil, err
	}
	return []Event{ev}, nil
}
