package server

import (
    "testing"
    "time"

    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/compiler"
    "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang/dag"
)

// Minimal integration test for correlation value_count (bruteforce via OpenSSH on Windows)
func TestCorrelationValueCount_OpenSSHBruteforce(t *testing.T) {
    ruleYAML := `
title: Brutforce on Windows OpenSSH server with valid users
name: bruteforce_openssh_vaild_users
description: Detects scenarios where an attacker attempts to SSH brutforce a Windows OpenSSH server with a valid user.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    SubStatus: "0xc000006A"
    ProcessName|endswith:
      - '\\sshd.exe'
      - '\\ssh.exe'
  condition: selection
level: high

---
title: Brutforce on Windows OpenSSH server with valid users Count
status: experimental
correlation:
  type: value_count
  rules:
    - bruteforce_openssh_vaild_users
  group-by:
    - Computer
  timespan: 30m
  condition:
    gte: 20
    field: EventRecordID
level: high
`

    c := compiler.New()
    if _, err := c.CompileRule(ruleYAML); err != nil {
        t.Fatalf("compile rule: %v", err)
    }
    rs := c.IntoRuleset()
    eng, err := dag.FromRuleset(rs, dag.DefaultEngineConfig())
    if err != nil { t.Fatalf("FromRuleset: %v", err) }

    // Build rule id -> name mapping
    ruleNames := make(map[uint32]string)
    for _, r := range rs.Rules {
        if r.RuleName != "" {
            ruleNames[uint32(r.RuleId)] = r.RuleName
        } else if r.Title != "" {
            ruleNames[uint32(r.RuleId)] = r.Title
        }
    }

    cm := NewCorrelationManagerFromIR(rs.Correlations)
    if cm == nil { t.Fatalf("corr mgr nil") }

    base := time.Now().UTC()
    corrHits := 0
    for i := 1; i <= 20; i++ {
        ev := map[string]any{
            "EventID":       4625,
            "SubStatus":     "0xc000006A",
            "ProcessName":   `C:\\Windows\\System32\\OpenSSH\\sshd.exe`,
            "Computer":      "HOST-A",
            "EventRecordID": i, // distinct to count events
        }
        res, err := eng.Evaluate(ev)
        if err != nil { t.Fatalf("evaluate: %v", err) }
        if len(res.MatchedRules) == 0 { t.Fatalf("expected base rule match at i=%d", i) }
        names := make([]string, 0, len(res.MatchedRules))
        for _, rid := range res.MatchedRules {
            if n, ok := ruleNames[uint32(rid)]; ok { names = append(names, n) }
        }
        hits := cm.Observe(ev, names, base.Add(time.Duration(i)*time.Minute))
        corrHits += len(hits)
        if i < 20 && corrHits != 0 {
            t.Fatalf("unexpected correlation hit before threshold at i=%d", i)
        }
    }
    if corrHits != 1 {
        t.Fatalf("expected exactly 1 correlation hit, got %d", corrHits)
    }
}

