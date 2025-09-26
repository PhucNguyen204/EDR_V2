package processtree

import (
	"sync"
	"time"
)

// ProcessTreeCorrelationEngine xử lý correlation giữa process tree và detections
type ProcessTreeCorrelationEngine struct {
	mu           sync.RWMutex
	correlations map[string]*ProcessCorrelation
	conditions   *ProcessTreeConditions
}

// ProcessCorrelation thông tin correlation của một process
type ProcessCorrelation struct {
	ProcessKey       string                 `json:"process_key"`
	EndpointID       string                 `json:"endpoint_id"`
	ProcessInfo      ProcessInfo            `json:"process_info"`
	Detections       []DetectionInfo        `json:"detections"`
	CorrelationScore float64                `json:"correlation_score"`
	LastUpdated      time.Time              `json:"last_updated"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// DetectionInfo thông tin detection liên quan
type DetectionInfo struct {
	DetectionID string                 `json:"detection_id"`
	RuleID      int32                  `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Timestamp   time.Time              `json:"timestamp"`
	Context     map[string]interface{} `json:"context"`
}

// CorrelationResult kết quả correlation
type CorrelationResult struct {
	ProcessKey        string          `json:"process_key"`
	EndpointID        string          `json:"endpoint_id"`
	CorrelationScore  float64         `json:"correlation_score"`
	RiskLevel         string          `json:"risk_level"`
	DetectedThreats   []string        `json:"detected_threats"`
	ProcessChain      []ProcessInfo   `json:"process_chain"`
	RelatedDetections []DetectionInfo `json:"related_detections"`
	Recommendations   []string        `json:"recommendations"`
	Timestamp         time.Time       `json:"timestamp"`
}

// NewProcessTreeCorrelationEngine tạo correlation engine mới
func NewProcessTreeCorrelationEngine(conditions *ProcessTreeConditions) *ProcessTreeCorrelationEngine {
	return &ProcessTreeCorrelationEngine{
		correlations: make(map[string]*ProcessCorrelation),
		conditions:   conditions,
	}
}

// AddDetection thêm detection vào correlation engine
func (e *ProcessTreeCorrelationEngine) AddDetection(detection DetectionInfo, processKey string, endpointID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	correlation, exists := e.correlations[processKey]
	if !exists {
		correlation = &ProcessCorrelation{
			ProcessKey:  processKey,
			EndpointID:  endpointID,
			Detections:  []DetectionInfo{},
			Metadata:    make(map[string]interface{}),
			LastUpdated: time.Now().UTC(),
		}
		e.correlations[processKey] = correlation
	}

	// Thêm detection
	correlation.Detections = append(correlation.Detections, detection)
	correlation.LastUpdated = time.Now().UTC()

	// Tính toán correlation score
	e.calculateCorrelationScore(correlation)
}

// AddProcessInfo thêm thông tin process vào correlation
func (e *ProcessTreeCorrelationEngine) AddProcessInfo(processKey string, endpointID string, processInfo ProcessInfo) {
	e.mu.Lock()
	defer e.mu.Unlock()

	correlation, exists := e.correlations[processKey]
	if !exists {
		correlation = &ProcessCorrelation{
			ProcessKey:  processKey,
			EndpointID:  endpointID,
			Detections:  []DetectionInfo{},
			Metadata:    make(map[string]interface{}),
			LastUpdated: time.Now().UTC(),
		}
		e.correlations[processKey] = correlation
	}

	correlation.ProcessInfo = processInfo
	correlation.LastUpdated = time.Now().UTC()

	// Tính toán correlation score
	e.calculateCorrelationScore(correlation)
}

// calculateCorrelationScore tính toán điểm correlation
func (e *ProcessTreeCorrelationEngine) calculateCorrelationScore(correlation *ProcessCorrelation) {
	score := 0.0

	// Điểm cơ bản dựa trên số lượng detections
	score += float64(len(correlation.Detections)) * 0.3

	// Điểm dựa trên severity của detections
	for _, detection := range correlation.Detections {
		switch detection.Severity {
		case "critical":
			score += 0.4
		case "high":
			score += 0.3
		case "medium":
			score += 0.2
		case "low":
			score += 0.1
		}
	}

	// Điểm dựa trên confidence
	for _, detection := range correlation.Detections {
		score += detection.Confidence * 0.2
	}

	// Điểm dựa trên thời gian (detections gần đây có điểm cao hơn)
	now := time.Now().UTC()
	for _, detection := range correlation.Detections {
		timeDiff := now.Sub(detection.Timestamp)
		if timeDiff < e.conditions.CorrelationTimeWindow {
			score += 0.1
		}
	}

	// Điểm dựa trên process đáng ngờ
	if e.conditions.IsSuspiciousProcess(Event{
		Executable:  correlation.ProcessInfo.Executable,
		CommandLine: correlation.ProcessInfo.CommandLine,
		Timestamp:   correlation.ProcessInfo.Timestamp,
	}) {
		score += 0.2
	}

	correlation.CorrelationScore = score
}

// GetCorrelationResult lấy kết quả correlation cho một process
func (e *ProcessTreeCorrelationEngine) GetCorrelationResult(processKey string) (*CorrelationResult, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	correlation, exists := e.correlations[processKey]
	if !exists {
		return nil, false
	}

	result := &CorrelationResult{
		ProcessKey:        processKey,
		EndpointID:        correlation.EndpointID,
		CorrelationScore:  correlation.CorrelationScore,
		RelatedDetections: correlation.Detections,
		Timestamp:         time.Now().UTC(),
	}

	// Xác định risk level
	if result.CorrelationScore >= 2.0 {
		result.RiskLevel = "critical"
	} else if result.CorrelationScore >= 1.5 {
		result.RiskLevel = "high"
	} else if result.CorrelationScore >= 1.0 {
		result.RiskLevel = "medium"
	} else {
		result.RiskLevel = "low"
	}

	// Tìm detected threats
	result.DetectedThreats = e.extractThreats(correlation.Detections)

	// Tạo recommendations
	result.Recommendations = e.generateRecommendations(result)

	return result, true
}

// GetAllCorrelations lấy tất cả correlations
func (e *ProcessTreeCorrelationEngine) GetAllCorrelations() map[string]*ProcessCorrelation {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make(map[string]*ProcessCorrelation)
	for key, correlation := range e.correlations {
		result[key] = correlation
	}
	return result
}

// GetHighRiskCorrelations lấy các correlations có risk cao
func (e *ProcessTreeCorrelationEngine) GetHighRiskCorrelations() []*CorrelationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var results []*CorrelationResult
	for _, correlation := range e.correlations {
		if correlation.CorrelationScore >= 1.0 {
			if result, ok := e.GetCorrelationResult(correlation.ProcessKey); ok {
				results = append(results, result)
			}
		}
	}
	return results
}

// extractThreats trích xuất các threats từ detections
func (e *ProcessTreeCorrelationEngine) extractThreats(detections []DetectionInfo) []string {
	threats := make(map[string]bool)

	for _, detection := range detections {
		// Trích xuất threat từ rule name
		if detection.RuleName != "" {
			threats[detection.RuleName] = true
		}

		// Trích xuất threat từ context
		if detection.Context != nil {
			if threatType, ok := detection.Context["threat_type"]; ok {
				if threatStr, ok := threatType.(string); ok {
					threats[threatStr] = true
				}
			}
		}
	}

	var result []string
	for threat := range threats {
		result = append(result, threat)
	}
	return result
}

// generateRecommendations tạo recommendations dựa trên correlation result
func (e *ProcessTreeCorrelationEngine) generateRecommendations(result *CorrelationResult) []string {
	var recommendations []string

	if result.RiskLevel == "critical" {
		recommendations = append(recommendations, "Immediate investigation required")
		recommendations = append(recommendations, "Consider isolating the endpoint")
		recommendations = append(recommendations, "Review process chain for lateral movement")
	} else if result.RiskLevel == "high" {
		recommendations = append(recommendations, "Priority investigation required")
		recommendations = append(recommendations, "Monitor for additional suspicious activity")
		recommendations = append(recommendations, "Review process execution logs")
	} else if result.RiskLevel == "medium" {
		recommendations = append(recommendations, "Schedule investigation")
		recommendations = append(recommendations, "Monitor process behavior")
	}

	// Recommendations dựa trên detected threats
	for _, threat := range result.DetectedThreats {
		switch threat {
		case "powershell_suspicious":
			recommendations = append(recommendations, "Review PowerShell execution policy")
			recommendations = append(recommendations, "Check for encoded commands")
		case "process_injection":
			recommendations = append(recommendations, "Scan for malware")
			recommendations = append(recommendations, "Check for DLL hijacking")
		case "lateral_movement":
			recommendations = append(recommendations, "Review network connections")
			recommendations = append(recommendations, "Check for credential theft")
		}
	}

	return recommendations
}

// CleanupExpiredCorrelations dọn dẹp các correlations đã hết hạn
func (e *ProcessTreeCorrelationEngine) CleanupExpiredCorrelations() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now().UTC()
	expiredTime := now.Add(-e.conditions.CorrelationTimeWindow * 2) // Giữ lại 2x time window

	for key, correlation := range e.correlations {
		if correlation.LastUpdated.Before(expiredTime) {
			delete(e.correlations, key)
		}
	}
}

// GetCorrelationStats trả về thống kê correlation
func (e *ProcessTreeCorrelationEngine) GetCorrelationStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := map[string]interface{}{
		"total_correlations": len(e.correlations),
		"high_risk_count":    0,
		"medium_risk_count":  0,
		"low_risk_count":     0,
		"average_score":      0.0,
	}

	totalScore := 0.0
	for _, correlation := range e.correlations {
		totalScore += correlation.CorrelationScore

		if correlation.CorrelationScore >= 1.5 {
			stats["high_risk_count"] = stats["high_risk_count"].(int) + 1
		} else if correlation.CorrelationScore >= 1.0 {
			stats["medium_risk_count"] = stats["medium_risk_count"].(int) + 1
		} else {
			stats["low_risk_count"] = stats["low_risk_count"].(int) + 1
		}
	}

	if len(e.correlations) > 0 {
		stats["average_score"] = totalScore / float64(len(e.correlations))
	}

	return stats
}
