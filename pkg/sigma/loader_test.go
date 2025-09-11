package sigma

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFieldKey(t *testing.T) {
	tests := []struct {
		input   string
		field   string
		op      Operator
		mods    PredicateModifiers
		wantErr bool
	}{
		{
			input: "Image",
			field: "Image",
			op:    OpEq,
			mods:  PredicateModifiers{},
		},
		{
			input: "CommandLine|contains",
			field: "CommandLine",
			op:    OpContains,
			mods:  PredicateModifiers{},
		},
		{
			input: "CommandLine|contains|cased",
			field: "CommandLine",
			op:    OpContains,
			mods:  PredicateModifiers{CaseSensitive: true},
		},
		{
			input: "CommandLine|re|wide",
			field: "CommandLine",
			op:    OpRegex,
			mods:  PredicateModifiers{Wide: true, UTF16LE: true},
		},
		{
			input: "CommandLine|contains|all",
			field: "CommandLine",
			op:    OpContains,
			mods:  PredicateModifiers{RequireAllVals: true},
		},
		{
			input: "CommandLine|endswith|base64",
			field: "CommandLine",
			op:    OpEndsWith,
			mods:  PredicateModifiers{Base64: true},
		},
		{
			input: "CommandLine|startswith|windash",
			field: "CommandLine",
			op:    OpStartsWith,
			mods:  PredicateModifiers{Windash: true},
		},
		{
			input: "CommandLine|exists",
			field: "CommandLine",
			op:    OpExists,
			mods:  PredicateModifiers{},
		},
		{
			input: "CommandLine|cidr",
			field: "CommandLine",
			op:    OpCidr,
			mods:  PredicateModifiers{},
		},
		{
			input: "CommandLine|lt",
			field: "CommandLine",
			op:    OpLt,
			mods:  PredicateModifiers{},
		},
		{
			input: "CommandLine|gt",
			field: "CommandLine",
			op:    OpGt,
			mods:  PredicateModifiers{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			field, op, mods, err := parseFieldKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFieldKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if field != tt.field {
				t.Errorf("parseFieldKey() field = %v, want %v", field, tt.field)
			}
			if op != tt.op {
				t.Errorf("parseFieldKey() op = %v, want %v", op, tt.op)
			}
			if mods != tt.mods {
				t.Errorf("parseFieldKey() mods = %v, want %v", mods, tt.mods)
			}
		})
	}
}

func TestCollectLiterals(t *testing.T) {
	selections := map[string]Selection{
		"keywords": {
			Name: "keywords",
			Groups: []SelectionGroup{
				{
					Predicates: []SelectionPredicate{
						{Field: "CommandLine", Op: OpContains, Value: "powershell"},
						{Field: "CommandLine", Op: OpContains, Value: "cmd"},
						{Field: "CommandLine", Op: OpRegex, Value: ".*test.*"},
						{Field: "CommandLine", Op: OpExists, Value: true},
						{Field: "CommandLine", Op: OpContains, Value: []any{"arg1", "arg2"}},
					},
				},
			},
		},
	}

	literals := collectLiterals(selections)

	expected := map[string]struct{}{
		"powershell": {},
		"cmd":        {},
		"arg1":       {},
		"arg2":       {},
	}

	if len(literals) != len(expected) {
		t.Errorf("Expected %d literals, got %d", len(expected), len(literals))
	}

	for expectedLiteral := range expected {
		if _, exists := literals[expectedLiteral]; !exists {
			t.Errorf("Expected literal '%s' not found", expectedLiteral)
		}
	}

	// Kiểm tra regex và exists không được thêm vào
	if _, exists := literals[".*test.*"]; exists {
		t.Error("Regex pattern should not be in literals")
	}
}

func TestLoadRuleFromTestData(t *testing.T) {
	// Đọc tất cả files .yml từ thư mục testdata/rules
	testDataDir := "../../testdata/rules"

	files, err := filepath.Glob(filepath.Join(testDataDir, "*.yml"))
	if err != nil {
		t.Fatalf("Failed to read testdata directory: %v", err)
	}

	if len(files) == 0 {
		t.Skip("No test rules found in testdata/rules")
	}

	for _, file := range files {
		filename := filepath.Base(file)
		t.Run(filename, func(t *testing.T) {
			// Đọc file từ testdata
			yamlData, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", filename, err)
			}

			rule, err := LoadRuleYAML(yamlData)
			if err != nil {
				t.Fatalf("Failed to load rule %s: %v", filename, err)
			}

			// Kiểm tra các thuộc tính cơ bản
			if rule.Title == "" {
				t.Error("Rule title should not be empty")
			}

			if rule.ID == "" {
				t.Error("Rule ID should not be empty")
			}

			if len(rule.Selections) == 0 {
				t.Error("Rule should have at least one selection")
			}

			if rule.Condition == "" {
				t.Error("Rule should have a condition")
			}

			// Kiểm tra logsource
			if rule.Logsource == nil {
				t.Error("Rule should have logsource")
			}

			// Kiểm tra literals được thu thập
			if len(rule.Literals) == 0 {
				t.Error("Rule should have some literals collected")
			}

			// Log thông tin rule để debug
			t.Logf("Loaded rule: %s (ID: %s)", rule.Title, rule.ID)
			t.Logf("Selections: %d, Literals: %d", len(rule.Selections), len(rule.Literals))
		})
	}
}
