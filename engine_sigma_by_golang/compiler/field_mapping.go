package compiler

import "maps"

// FieldMapping cấu hình ánh xạ tên field để “chuẩn hoá” theo taxonomy SIGMA
// hoặc tuỳ chỉnh theo môi trường triển khai.
type FieldMapping struct {
	fieldMap map[string]string
	taxonomy string
}

// NewFieldMapping tạo FieldMapping rỗng với taxonomy mặc định "sigma".
func NewFieldMapping() FieldMapping {
	return FieldMapping{
		fieldMap: make(map[string]string),
		taxonomy: "sigma",
	}
}

// WithTaxonomy tạo FieldMapping rỗng với taxonomy chỉ định.
func WithTaxonomy(taxonomy string) FieldMapping {
	return FieldMapping{
		fieldMap: make(map[string]string),
		taxonomy: taxonomy,
	}
}

// LoadTaxonomyMappings nạp các ánh xạ field từ một taxonomy config (map).
// Thao tác này ghi đè các key trùng.
func (fm *FieldMapping) LoadTaxonomyMappings(mappings map[string]string) {
	if fm.fieldMap == nil {
		fm.fieldMap = make(map[string]string)
	}
	for k, v := range mappings {
		fm.fieldMap[k] = v
	}
}

// AddMapping thêm một ánh xạ field tuỳ chỉnh.
func (fm *FieldMapping) AddMapping(sourceField, targetField string) {
	if fm.fieldMap == nil {
		fm.fieldMap = make(map[string]string)
	}
	fm.fieldMap[sourceField] = targetField
}

// Taxonomy trả về tên taxonomy hiện tại.
func (fm FieldMapping) Taxonomy() string {
	return fm.taxonomy
}

// SetTaxonomy đặt lại tên taxonomy.
func (fm *FieldMapping) SetTaxonomy(taxonomy string) {
	fm.taxonomy = taxonomy
}

// NormalizeField chuẩn hoá tên field theo mapping;
// nếu không có mapping, trả lại nguyên văn field đầu vào (theo spec SIGMA).
func (fm FieldMapping) NormalizeField(fieldName string) string {
	if v, ok := fm.fieldMap[fieldName]; ok {
		return v
	}
	return fieldName
}

// HasMapping kiểm tra có ánh xạ cho field hay không.
func (fm FieldMapping) HasMapping(fieldName string) bool {
	_, ok := fm.fieldMap[fieldName]
	return ok
}

// Mappings trả về một bản sao (copy) các ánh xạ hiện có.
// Trả về copy để tránh bị thay đổi từ bên ngoài (tương đương &HashMap trong Rust – bất biến).
func (fm FieldMapping) Mappings() map[string]string {
	if fm.fieldMap == nil {
		return map[string]string{}
	}
	// Go 1.21+: maps.Clone; nếu dùng Go cũ hơn, thay bằng vòng lặp copy thủ công.
	return maps.Clone(fm.fieldMap)
}
