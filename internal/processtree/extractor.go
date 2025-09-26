package processtree

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ExtractEventFromLog chuyen log map thanh Event phuc vu cap nhat cay.
func ExtractEventFromLog(endpointID string, raw map[string]any) (Event, bool) {
	evt := Event{EndpointID: endpointID}

	// Thử các cấu trúc khác nhau của event
	// 1. Cấu trúc ECS chuẩn
	evt.EntityID = toString(resolve(raw, "process.entity_id"))
	evt.ParentEntityID = toString(resolve(raw, "process.parent.entity_id"))
	evt.PID = normalizePID(resolve(raw, "process.pid"))
	evt.PPID = normalizePID(resolve(raw, "process.parent.pid"))
	evt.Name = toString(resolve(raw, "process.name"))
	evt.Executable = toString(resolve(raw, "process.executable"))
	evt.CommandLine = toString(resolve(raw, "process.command_line"))

	// 2. Cấu trúc từ Vector transform (event_data)
	if evt.PID == "" {
		evt.PID = normalizePID(resolve(raw, "event_data.ProcessId"))
	}
	if evt.PPID == "" {
		evt.PPID = normalizePID(resolve(raw, "event_data.ParentProcessId"))
	}
	if evt.Executable == "" {
		evt.Executable = toString(resolve(raw, "event_data.Image"))
	}
	if evt.CommandLine == "" {
		evt.CommandLine = toString(resolve(raw, "event_data.CommandLine"))
	}
	if evt.Name == "" {
		evt.Name = toString(resolve(raw, "event_data.OriginalFileName"))
	}

	// 3. Cấu trúc từ winlog.event_data
	if evt.PID == "" {
		evt.PID = normalizePID(resolve(raw, "winlog.event_data.ProcessId"))
	}
	if evt.PPID == "" {
		evt.PPID = normalizePID(resolve(raw, "winlog.event_data.ParentProcessId"))
	}
	if evt.Executable == "" {
		evt.Executable = toString(resolve(raw, "winlog.event_data.Image"))
	}
	if evt.CommandLine == "" {
		evt.CommandLine = toString(resolve(raw, "winlog.event_data.CommandLine"))
	}
	if evt.Name == "" {
		evt.Name = toString(resolve(raw, "winlog.event_data.OriginalFileName"))
	}

	// 4. Sử dụng ProcessGuid làm EntityID nếu có
	if evt.EntityID == "" {
		evt.EntityID = toString(resolve(raw, "event_data.ProcessGuid"))
	}
	if evt.EntityID == "" {
		evt.EntityID = toString(resolve(raw, "winlog.event_data.ProcessGuid"))
	}
	if evt.ParentEntityID == "" {
		evt.ParentEntityID = toString(resolve(raw, "event_data.ParentProcessGuid"))
	}
	if evt.ParentEntityID == "" {
		evt.ParentEntityID = toString(resolve(raw, "winlog.event_data.ParentProcessGuid"))
	}

	if evt.EntityID == "" && evt.PID == "" {
		// Khong du thong tin de ghep vao cay.
		return Event{}, false
	}

	if ts := toString(resolve(raw, "@timestamp")); ts != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			evt.Timestamp = parsed
		}
	}
	if evt.Timestamp.IsZero() {
		if ts := toString(resolve(raw, "event.ingested")); ts != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				evt.Timestamp = parsed
			}
		}
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}

	return evt, true
}

func resolve(raw map[string]any, path string) any {
	if raw == nil {
		return nil
	}
	if v, ok := raw[path]; ok {
		return v
	}
	parts := strings.Split(path, ".")
	current := any(raw)
	for _, p := range parts {
		mm, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		val, ok := mm[p]
		if !ok {
			return nil
		}
		current = val
	}
	return current
}

func toString(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(val), 'f', -1, 32)
	case int:
		return strconv.Itoa(val)
	case int32:
		return strconv.FormatInt(int64(val), 10)
	case int64:
		return strconv.FormatInt(val, 10)
	case uint:
		return strconv.FormatUint(uint64(val), 10)
	case uint32:
		return strconv.FormatUint(uint64(val), 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case fmt.Stringer:
		return val.String()
	default:
		return ""
	}
}

func normalizePID(v any) string {
	s := toString(v)
	if s == "" {
		return ""
	}
	return strings.TrimSpace(s)
}
