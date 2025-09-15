package compiler

import "testing"

func TestFieldMappingCreation(t *testing.T) {
	m := NewFieldMapping()
	if m.Taxonomy() != "sigma" {
		t.Fatalf("taxonomy = %q, want %q", m.Taxonomy(), "sigma")
	}
	if len(m.Mappings()) != 0 {
		t.Fatalf("mappings len = %d, want 0", len(m.Mappings()))
	}
}

func TestFieldMappingWithTaxonomy(t *testing.T) {
	m := WithTaxonomy("custom")
	if m.Taxonomy() != "custom" {
		t.Fatalf("taxonomy = %q, want %q", m.Taxonomy(), "custom")
	}
}

func TestAddMapping(t *testing.T) {
	m := NewFieldMapping()
	m.AddMapping("Event_ID", "EventID")

	if !m.HasMapping("Event_ID") {
		t.Fatalf("expected HasMapping(Event_ID) = true")
	}
	if got := m.NormalizeField("Event_ID"); got != "EventID" {
		t.Fatalf("NormalizeField(Event_ID) = %q, want %q", got, "EventID")
	}
}

func TestLoadTaxonomyMappings(t *testing.T) {
	m := NewFieldMapping()
	maps := map[string]string{
		"Event_ID":    "EventID",
		"Process_Name": "Image",
	}
	m.LoadTaxonomyMappings(maps)

	if len(m.Mappings()) != 2 {
		t.Fatalf("mappings len = %d, want 2", len(m.Mappings()))
	}
	if got := m.NormalizeField("Event_ID"); got != "EventID" {
		t.Fatalf("NormalizeField(Event_ID) = %q, want %q", got, "EventID")
	}
	if got := m.NormalizeField("Process_Name"); got != "Image" {
		t.Fatalf("NormalizeField(Process_Name) = %q, want %q", got, "Image")
	}
}

func TestNormalizeFieldUnmapped(t *testing.T) {
	m := NewFieldMapping()
	if got := m.NormalizeField("UnmappedField"); got != "UnmappedField" {
		t.Fatalf("NormalizeField(UnmappedField) = %q, want %q", got, "UnmappedField")
	}
}

func TestSetTaxonomy(t *testing.T) {
	m := NewFieldMapping()
	m.SetTaxonomy("custom")
	if m.Taxonomy() != "custom" {
		t.Fatalf("taxonomy = %q, want %q", m.Taxonomy(), "custom")
	}
}

// Rust có impl Default -> new(). Trong Go, ta dùng NewFieldMapping làm “mặc định”.
func TestDefaultImplementation(t *testing.T) {
	m := NewFieldMapping()
	if m.Taxonomy() != "sigma" {
		t.Fatalf("taxonomy = %q, want %q", m.Taxonomy(), "sigma")
	}
	if len(m.Mappings()) != 0 {
		t.Fatalf("mappings len = %d, want 0", len(m.Mappings()))
	}
}
