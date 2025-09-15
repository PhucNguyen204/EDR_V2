package tests

import (
    "testing"

    comp "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    dag "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/matcher"
)

// Rule: HackTool - CrackMapExec Process Patterns
// Event: cmd.exe /c powershell ...
// Expectation with current engine: SHOULD NOT MATCH (needs at least one full selection satisfied)
func TestCrackMapExecPatterns_DoesNotMatchSimpleCmdWhoami(t *testing.T) {
    ruleYAML := `
title: HackTool - CrackMapExec Process Patterns
id: f26307d8-14cd-47e3-a26b-4b4769f24af6
status: test
description: Detects suspicious process patterns found in logs when CrackMapExec is used
references:
  - https://mpgn.gitbook.io/crackmapexec/smb-protocol/obtaining-credentials/dump-lsass
author: Florian Roth (Nextron Systems)
date: 2022-03-12
modified: 2023-02-13
tags: [attack.credential-access, attack.t1003.001]
logsource:
  product: windows
  category: process_creation
detection:
  selection_lsass_dump1:
    CommandLine|contains|all:
      - 'tasklist /fi '
      - 'Imagename eq lsass.exe'
    CommandLine|contains:
      - 'cmd.exe /c '
      - 'cmd.exe /r '
      - 'cmd.exe /k '
      - 'cmd /c '
      - 'cmd /r '
      - 'cmd /k '
    User|contains:
      - 'AUTHORI'
      - 'AUTORI'
  selection_lsass_dump2:
    CommandLine|contains|all:
      - 'do rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump'
      - '\\Windows\\Temp\\'
      - ' full'
      - '%%B'
  selection_procdump:
    CommandLine|contains|all:
      - 'tasklist /v /fo csv'
      - 'findstr /i "lsass"'
  condition: 1 of selection*
level: high
`

    // Compile rule
    c := comp.New()
    rs, err := c.CompileRuleset([]string{ruleYAML})
    if err != nil { t.Fatalf("compile ruleset: %v", err) }

    // Build DAG engine
    eng, err := dag.FromRuleset(rs, dag.DefaultEngineConfig())
    if err != nil { t.Fatalf("build engine: %v", err) }

    // Event under test
    ev := map[string]any{
        "Image":        "C\\\\Windows\\\\System32\\\\cmd.exe",
        "CommandLine":  "cmd.exe /c powershell.exe -nop -w hidden -enc SQBFAFgAIA...",
        "User":         "CORP\\jane.doe",
        "ParentImage":  "C\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE",
        "endpoint_id":  "HR-LAPTOP-01",
    }

    // Evaluate
    res, err := eng.Evaluate(ev)
    if err != nil { t.Fatalf("evaluate: %v", err) }

    // Debug: list which primitives (by index + field/match/values) matched on this event
    for i, p := range rs.Primitives {
        cp, err := matcher.FromPrimitive(p)
        if err != nil { t.Fatalf("compile primitive %d: %v", i, err) }
        ok := cp.Matches(matcher.NewEventContext(ev))
        t.Logf("primitive[%d] field=%s match=%s values=%v => %v", i, p.Field, p.MatchType, p.Values, ok)
    }

    if len(res.MatchedRules) != 0 {
        t.Fatalf("expected no match, got rules=%v", res.MatchedRules)
    }
}

