package sigma

import "strings"

type FieldMapping struct{ M map[string]string }

func NewFieldMapping(m map[string]string) FieldMapping {
	if m == nil { m = map[string]string{} }
	return FieldMapping{M: m}
}

func (fm FieldMapping) Resolve(field string) string {
	if v, ok := fm.M[field]; ok { return v }
	if v, ok := fm.M[strings.ToLower(field)]; ok { return v }
	return field
}
