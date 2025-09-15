package matcher

// Core type definitions for the zero-allocation functional registry.


// MatchFn là chữ ký hàm so khớp zero-allocation.
// Nhận fieldValue và 2 lát cắt values/modifiers (không copy), trả về (true) nếu
// bất kỳ giá trị nào khớp theo logic của match type tương ứng.
type MatchFn func(fieldValue string, values []string, modifiers []string) (bool, error)

// ModifierFn là bộ xử lý modifier theo chuỗi, áp dụng tuần tự khi evaluate primitive.
type ModifierFn func(input string) (string, error)

// EventContext mô tả ngữ cảnh sự kiện (và cache) cho trích xuất field.
// Bạn có thể mở rộng trong engine của bạn; ở đây chỉ là khung tối thiểu.


// FieldExtractorFn trích xuất giá trị field từ EventContext.
// Trả về (value, present, error).
// - present=false nếu không tìm thấy.
// - error != nil nếu trích xuất thất bại.
type FieldExtractorFn func(ctx *EventContext, field string) (string, bool, error)

// --- Ví dụ triển khai tham khảo (tuỳ chọn dùng trong test/POC) ---

// GetFieldSimple là tiện ích tối thiểu để minh hoạ cách trích xuất một field phẳng.
// Bạn có thể thay bằng logic JSON-path thực sự trong engine của bạn.
