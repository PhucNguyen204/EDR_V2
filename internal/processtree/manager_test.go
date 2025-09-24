package processtree

import (
    "testing"
    "time"
)

func TestManagerBuildTree(t *testing.T) {
    mgr := NewManager()
    ts := time.Now().UTC()

    mgr.Upsert(Event{
        EndpointID: "agent-1",
        EntityID:   "proc-parent",
        PID:        "4321",
        Timestamp:  ts,
        Name:       "parent.exe",
    })

    mgr.Upsert(Event{
        EndpointID:     "agent-1",
        EntityID:       "proc-child",
        ParentEntityID: "proc-parent",
        PID:            "5000",
        PPID:           "4321",
        Name:           "child.exe",
        Timestamp:      ts.Add(time.Second),
    })

    snap, ok := mgr.Snapshot("agent-1", "")
    if !ok {
        t.Fatalf("khong tim thay endpoint")
    }
    if len(snap) != 1 {
        t.Fatalf("expected 1 root, got %d", len(snap))
    }
    root := snap[0]
    if root.EntityID != "proc-parent" {
        t.Fatalf("root entity mismatch: %s", root.EntityID)
    }
    if len(root.Children) != 1 {
        t.Fatalf("expected 1 child, got %d", len(root.Children))
    }
    child := root.Children[0]
    if child.EntityID != "proc-child" {
        t.Fatalf("child entity mismatch: %s", child.EntityID)
    }
    if child.PPID != "4321" {
        t.Fatalf("expected PPID 4321, got %s", child.PPID)
    }
}

func TestManagerFallbackPID(t *testing.T) {
    mgr := NewManager()
    mgr.Upsert(Event{EndpointID: "agent-1", PID: "100"})
    mgr.Upsert(Event{EndpointID: "agent-1", PID: "200", PPID: "100"})

    snap, ok := mgr.Snapshot("agent-1", "")
    if !ok || len(snap) != 1 {
        t.Fatalf("snapshot khong hop le")
    }
    if len(snap[0].Children) != 1 {
        t.Fatalf("expected 1 child, got %d", len(snap[0].Children))
    }
}
