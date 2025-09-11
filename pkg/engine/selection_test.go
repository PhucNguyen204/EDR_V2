package engine

import (
	"testing"

	"github.com/PhucNguyen204/EDR_V2/pkg/sigma"
)

func fm() sigma.FieldMapping {
	return sigma.NewFieldMapping(map[string]string{
		"ProcessImage":       "Image",
		"ProcessCommandLine": "CommandLine",
	})
}

func TestSelection_AND_Group(t *testing.T) {
	// selection dạng mapping => 1 group AND
	sel := sigma.Selection{
		Name: "sel",
		Groups: []sigma.SelectionGroup{{
			Predicates: []sigma.SelectionPredicate{
				{Field: "ProcessImage", Op: sigma.OpEndsWith, Value: `\powershell.exe`},
				{Field: "ProcessCommandLine", Op: sigma.OpContains, Value: "Invoke-Expression"},
			},
		}},
	}
	ev := map[string]any{
		"Image":       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"CommandLine": `powershell.exe -nop -Command Invoke-Expression`,
	}
	if !evalSelection(ev, sel, fm()) {
		t.Fatalf("expected AND-group selection to match")
	}
}

func TestSelection_ORofAND_Groups(t *testing.T) {
	// selection dạng list => OR giữa các group
	sel := sigma.Selection{
		Name: "img7z",
		Groups: []sigma.SelectionGroup{
			{Predicates: []sigma.SelectionPredicate{
				{Field: "Description", Op: sigma.OpContains, Value: "7-Zip"},
			}},
			{Predicates: []sigma.SelectionPredicate{
				{Field: "Image", Op: sigma.OpEndsWith, Value: []any{`\7z.exe`, `\7za.exe`}},
			}},
			{Predicates: []sigma.SelectionPredicate{
				{Field: "OriginalFileName", Op: sigma.OpEq, Value: []any{`7z.exe`, `7za.exe`}},
			}},
		},
	}
	ev1 := map[string]any{"Description": "7-Zip Console"}
	ev2 := map[string]any{"Image": `C:\Program Files\7-Zip\7z.exe`}
	ev3 := map[string]any{"OriginalFileName": `7za.exe`}

	if !evalSelection(ev1, sel, sigma.NewFieldMapping(nil)) { t.Fatalf("OR group #1 failed") }
	if !evalSelection(ev2, sel, sigma.NewFieldMapping(nil)) { t.Fatalf("OR group #2 failed") }
	if !evalSelection(ev3, sel, sigma.NewFieldMapping(nil)) { t.Fatalf("OR group #3 failed") }
}

func TestSelection_ListAnyOf_WithCase(t *testing.T) {
	sel := sigma.Selection{
		Name: "cmd",
		Groups: []sigma.SelectionGroup{{
			Predicates: []sigma.SelectionPredicate{
				{Field: "CommandLine", Op: sigma.OpContains, Value: []any{" a ", " u "}},
			},
		}},
	}
	ev := map[string]any{"CommandLine": "7z.exe a out.7z C:\\data -pS3cret"}
	if !evalSelection(ev, sel, sigma.NewFieldMapping(nil)) {
		t.Fatalf("contains any-of failed")
	}

	// Case sensitive contains
	sel2 := sigma.Selection{
		Name: "cased",
		Groups: []sigma.SelectionGroup{{
			Predicates: []sigma.SelectionPredicate{
				{Field: "CommandLine", Op: sigma.OpContains, Value: "Invoke-Expression",
					Modifiers: sigma.PredicateModifiers{CaseSensitive: true}},
			},
		}},
	}
	ev2 := map[string]any{"CommandLine": "invoke-expression"} // lowercase
	if evalSelection(ev2, sel2, sigma.NewFieldMapping(nil)) {
		t.Fatalf("cased contains should fail for lowercase")
	}
}

func TestSelection_Regex_And_All(t *testing.T) {
	// Regex
	selRe := sigma.Selection{
		Name: "re",
		Groups: []sigma.SelectionGroup{{
			Predicates: []sigma.SelectionPredicate{
				{Field: "CommandLine", Op: sigma.OpRegex, Value: `(?i)invoke-?\s*expression`},
			},
		}},
	}
	evRe := map[string]any{"CommandLine": "Invoke-Expression"}
	if !evalSelection(evRe, selRe, sigma.NewFieldMapping(nil)) {
		t.Fatalf("regex should match")
	}

	// OpAll: mọi phần tử của field list phải chứa needle
	selAll := sigma.Selection{
		Name: "modsAll",
		Groups: []sigma.SelectionGroup{{
			Predicates: []sigma.SelectionPredicate{
				{Field: "modules", Op: sigma.OpAll, Value: `C:\`},
			},
		}},
	}
	evOk := map[string]any{"modules": []any{`C:\a.dll`, `C:\b.dll`}}
	evBad := map[string]any{"modules": []any{`C:\a.dll`, `b.dll`}}
	if !evalSelection(evOk, selAll, sigma.NewFieldMapping(nil)) { t.Fatalf("OpAll should pass") }
	if evalSelection(evBad, selAll, sigma.NewFieldMapping(nil)) { t.Fatalf("OpAll should fail") }
}

func TestSelection_FieldMapping(t *testing.T) {
	sel := sigma.Selection{
		Name: "map",
		Groups: []sigma.SelectionGroup{{
			Predicates: []sigma.SelectionPredicate{
				{Field: "ProcessImage", Op: sigma.OpEq, Value: `C:\tool.exe`},
			},
		}},
	}
	ev := map[string]any{"Image": `C:\tool.exe`}
	if !evalSelection(ev, sel, fm()) {
		t.Fatalf("field mapping resolve failed")
	}
}

