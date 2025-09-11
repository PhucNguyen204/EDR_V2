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

func TestSelection_FieldMapping_ECSAliases(t *testing.T) {
    // ECS-style field mapped to classic CommandLine
    sel := sigma.Selection{
        Name: "ecs",
        Groups: []sigma.SelectionGroup{{
            Predicates: []sigma.SelectionPredicate{
                {Field: "process.command_line", Op: sigma.OpContains, Value: "Invoke-Expression"},
            },
        }},
    }
    ev := map[string]any{"CommandLine": "powershell -c Invoke-Expression"}
    fm := sigma.NewFieldMapping(map[string]string{"process.command_line": "CommandLine"})
    if !evalSelection(ev, sel, fm) {
        t.Fatalf("ECS alias mapping failed")
    }
}

func TestSelection_ListRequireAllVals(t *testing.T) {
    sel := sigma.Selection{
        Name: "allvals",
        Groups: []sigma.SelectionGroup{{
            Predicates: []sigma.SelectionPredicate{
                {Field: "CommandLine", Op: sigma.OpContains, Value: []any{" out.7z ", " -p"}, Modifiers: sigma.PredicateModifiers{RequireAllVals: true}},
            },
        }},
    }
    ev := map[string]any{"CommandLine": "7z.exe a out.7z C:/data -pS3cret"}
    if !evalSelection(ev, sel, sigma.NewFieldMapping(nil)) {
        t.Fatalf("RequireAllVals should match when all tokens present")
    }
}

func TestSelection_CIDR(t *testing.T) {
    sel := sigma.Selection{
        Name: "cidr",
        Groups: []sigma.SelectionGroup{{
            Predicates: []sigma.SelectionPredicate{
                {Field: "DestinationIp", Op: sigma.OpCidr, Value: "10.0.0.0/8"},
            },
        }},
    }
    ev := map[string]any{"network": map[string]any{"dst": map[string]any{"ip": "10.123.5.6"}}}
    fm := sigma.NewFieldMapping(map[string]string{"DestinationIp": "network.dst.ip"})
    if !evalSelection(ev, sel, fm) {
        t.Fatalf("CIDR should contain IP in subnet")
    }
}

func TestSelection_Exists(t *testing.T) {
    sel := sigma.Selection{
        Name: "exists",
        Groups: []sigma.SelectionGroup{{
            Predicates: []sigma.SelectionPredicate{{Field: "ParentImage", Op: sigma.OpExists, Value: true}},
        }},
    }
    ev := map[string]any{"ParentImage": "C:/Windows/Explorer.exe"}
    if !evalSelection(ev, sel, sigma.NewFieldMapping(nil)) {
        t.Fatalf("exists=true should pass when field present")
    }
    ev2 := map[string]any{"Image": "x"}
    if evalSelection(ev2, sel, sigma.NewFieldMapping(nil)) {
        t.Fatalf("exists=true should fail when field missing")
    }
}

func TestSelection_FieldRef(t *testing.T) {
    sel := sigma.Selection{
        Name: "fieldref",
        Groups: []sigma.SelectionGroup{{
            Predicates: []sigma.SelectionPredicate{
                {Field: "a", Op: sigma.OpEq, Value: "b", Modifiers: sigma.PredicateModifiers{FieldRef: true}},
            },
        }},
    }
    ev := map[string]any{"a": "Hello", "b": "Hello"}
    if !evalSelection(ev, sel, sigma.NewFieldMapping(nil)) {
        t.Fatalf("fieldref equality should match")
    }
}

func TestSelection_Base64Modifier(t *testing.T) {
    // Pattern 'Invoke-Expression' as base64 appears in CommandLine
    sel := sigma.Selection{
        Name: "b64",
        Groups: []sigma.SelectionGroup{{
            Predicates: []sigma.SelectionPredicate{
                {Field: "CommandLine", Op: sigma.OpContains, Value: "Invoke-Expression", Modifiers: sigma.PredicateModifiers{Base64: true}},
            },
        }},
    }
    // echo -n 'Invoke-Expression' | base64 => 'SW52b2tlLUV4cHJlc3Npb24='
    ev := map[string]any{"CommandLine": "powershell -enc SW52b2tlLUV4cHJlc3Npb24="}
    if !evalSelection(ev, sel, sigma.NewFieldMapping(nil)) {
        t.Fatalf("base64 modifier should match encoded payload")
    }
}

func TestSelection_DottedPathNested(t *testing.T) {
    sel := sigma.Selection{
        Name: "dotted",
        Groups: []sigma.SelectionGroup{{
            Predicates: []sigma.SelectionPredicate{
                {Field: "process.command_line", Op: sigma.OpContains, Value: "Invoke-Expression"},
            },
        }},
    }
    ev := map[string]any{"process": map[string]any{"command_line": "powershell -c Invoke-Expression"}}
    // No mapping needed; dotted path should resolve directly
    if !evalSelection(ev, sel, sigma.NewFieldMapping(nil)) {
        t.Fatalf("dotted path resolution for nested maps failed")
    }
}

func TestSelection_PowerShellScriptBlockMapping(t *testing.T) {
    sel := sigma.Selection{
        Name: "ps",
        Groups: []sigma.SelectionGroup{{
            Predicates: []sigma.SelectionPredicate{
                {Field: "ScriptBlockText", Op: sigma.OpContains, Value: "Invoke-Expression"},
            },
        }},
    }
    ev := map[string]any{"powershell": map[string]any{"script_block": "...Invoke-Expression..."}}
    // Mapping in app maps ScriptBlockText -> powershell.script_block
    fm := sigma.NewFieldMapping(map[string]string{"ScriptBlockText": "powershell.script_block"})
    if !evalSelection(ev, sel, fm) {
        t.Fatalf("ScriptBlockText mapping should resolve to powershell.script_block")
    }
}

func TestSelection_AnyKeywords(t *testing.T) {
    // __any contains scalar
    sel := sigma.Selection{
        Name: "kw",
        Groups: []sigma.SelectionGroup{{
            Predicates: []sigma.SelectionPredicate{
                {Field: "__any", Op: sigma.OpContains, Value: "SuspiciousOperation"},
            },
        }},
    }
    ev := map[string]any{"Message": "Django error: SuspiciousOperation in view"}
    if !evalSelection(ev, sel, sigma.NewFieldMapping(nil)) {
        t.Fatalf("__any scalar should match across fields")
    }

    // __any list any-of
    sel2 := sigma.Selection{
        Name: "kwlist",
        Groups: []sigma.SelectionGroup{{
            Predicates: []sigma.SelectionPredicate{
                {Field: "__any", Op: sigma.OpContains, Value: []any{"NotHere", "ProcessBuilder"}},
            },
        }},
    }
    ev2 := map[string]any{"CommandLine": "Cannot run program: java.lang.ProcessBuilder"}
    if !evalSelection(ev2, sel2, sigma.NewFieldMapping(nil)) {
        t.Fatalf("__any list any-of should match")
    }

    // __any list all-of
    sel3 := sigma.Selection{
        Name: "kwall",
        Groups: []sigma.SelectionGroup{{
            Predicates: []sigma.SelectionPredicate{
                {Field: "__any", Op: sigma.OpContains, Value: []any{"alpha", "beta"}, Modifiers: sigma.PredicateModifiers{RequireAllVals: true}},
            },
        }},
    }
    ev3 := map[string]any{"a": "alpha value", "b": "gamma beta"}
    if !evalSelection(ev3, sel3, sigma.NewFieldMapping(nil)) {
        t.Fatalf("__any list all-of should match when all keywords present in event")
    }
}

