package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/PhucNguyen204/EDR_V2/pkg/engine"
)

type AppServer struct {
	eng *engine.Engine
}

func NewAppServer(eng *engine.Engine) *AppServer { return &AppServer{eng: eng} }

func (s *AppServer) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/ingest", s.handleIngest)
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
			continue
		}
		out = append(out, evalResult{Index: i, Matched: ids})
		total += len(ids)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted": len(evs),
		"matched":  total,
		"results":  out,
	})
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
