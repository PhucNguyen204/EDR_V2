package engine

import "testing"

func TestAC_FindAny(t *testing.T) {
	pats := []string{"hello", "world", "powershell.exe"}
	ac := NewAC(pats)
	hits := ac.FindAny("**HeLLo** not here")
	if _, ok := hits[0]; !ok { t.Fatalf("missing match for hello") }
	hits2 := ac.FindAny("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe")
	if _, ok := hits2[2]; !ok { t.Fatalf("missing match for powershell.exe") }
}
