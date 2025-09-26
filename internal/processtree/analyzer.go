package processtree

import (
	"fmt"
	"strings"
	"time"
)

// ProcessTreeAnalyzer phân tích process tree để tìm patterns đáng ngờ
type ProcessTreeAnalyzer struct {
	conditions *ProcessTreeConditions
}

// NewProcessTreeAnalyzer tạo analyzer mới
func NewProcessTreeAnalyzer(conditions *ProcessTreeConditions) *ProcessTreeAnalyzer {
	return &ProcessTreeAnalyzer{
		conditions: conditions,
	}
}

// AnalysisResult kết quả phân tích process tree
type AnalysisResult struct {
	EndpointID          string            `json:"endpoint_id"`
	TotalProcesses      int               `json:"total_processes"`
	SuspiciousProcesses int               `json:"suspicious_processes"`
	TreeDepth           int               `json:"tree_depth"`
	RootProcesses       int               `json:"root_processes"`
	OrphanProcesses     int               `json:"orphan_processes"`
	SuspiciousChains    []SuspiciousChain `json:"suspicious_chains"`
	Anomalies           []Anomaly         `json:"anomalies"`
	ProcessStatistics   ProcessStatistics `json:"process_statistics"`
	AnalysisTimestamp   time.Time         `json:"analysis_timestamp"`
}

// SuspiciousChain chuỗi process đáng ngờ
type SuspiciousChain struct {
	ChainID      string        `json:"chain_id"`
	StartTime    time.Time     `json:"start_time"`
	EndTime      time.Time     `json:"end_time"`
	Duration     time.Duration `json:"duration"`
	ProcessCount int           `json:"process_count"`
	Processes    []ProcessInfo `json:"processes"`
	RiskLevel    string        `json:"risk_level"`
	Description  string        `json:"description"`
}

// ProcessInfo thông tin process trong chain
type ProcessInfo struct {
	Key          string    `json:"key"`
	PID          string    `json:"pid"`
	Name         string    `json:"name"`
	Executable   string    `json:"executable"`
	CommandLine  string    `json:"command_line"`
	Timestamp    time.Time `json:"timestamp"`
	IsSuspicious bool      `json:"is_suspicious"`
}

// Anomaly bất thường trong process tree
type Anomaly struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	ProcessKey  string                 `json:"process_key"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
}

// ProcessStatistics thống kê process
type ProcessStatistics struct {
	MostCommonExecutables map[string]int  `json:"most_common_executables"`
	MostCommonParents     map[string]int  `json:"most_common_parents"`
	AverageChildren       float64         `json:"average_children"`
	MaxChildren           int             `json:"max_children"`
	ProcessLifetimes      []time.Duration `json:"process_lifetimes"`
}

// AnalyzeTree phân tích toàn bộ process tree của endpoint
func (a *ProcessTreeAnalyzer) AnalyzeTree(manager *Manager, endpointID string) (*AnalysisResult, error) {
	snapshots, exists := manager.Snapshot(endpointID, "")
	if !exists {
		return nil, fmt.Errorf("endpoint %s not found", endpointID)
	}

	result := &AnalysisResult{
		EndpointID:        endpointID,
		AnalysisTimestamp: time.Now().UTC(),
		SuspiciousChains:  []SuspiciousChain{},
		Anomalies:         []Anomaly{},
		ProcessStatistics: ProcessStatistics{
			MostCommonExecutables: make(map[string]int),
			MostCommonParents:     make(map[string]int),
		},
	}

	// Phân tích từng root process
	for _, snapshot := range snapshots {
		a.analyzeNode(&snapshot, result, 0)
	}

	// Tính toán thống kê
	a.calculateStatistics(result)

	// Tìm suspicious chains
	a.findSuspiciousChains(result)

	// Tìm anomalies
	a.findAnomalies(result)

	return result, nil
}

// analyzeNode phân tích một node và các con của nó
func (a *ProcessTreeAnalyzer) analyzeNode(node *TreeSnapshot, result *AnalysisResult, depth int) {
	result.TotalProcesses++

	// Cập nhật độ sâu tối đa
	if depth > result.TreeDepth {
		result.TreeDepth = depth
	}

	// Kiểm tra process đáng ngờ
	if a.conditions.IsSuspiciousProcess(Event{
		Executable:  node.Executable,
		CommandLine: node.CommandLine,
		Timestamp:   node.LastSeen,
	}) {
		result.SuspiciousProcesses++
	}

	// Cập nhật thống kê
	if node.Executable != "" {
		result.ProcessStatistics.MostCommonExecutables[node.Executable]++
	}

	// Phân tích các con
	for _, child := range node.Children {
		a.analyzeNode(&child, result, depth+1)
	}
}

// calculateStatistics tính toán thống kê
func (a *ProcessTreeAnalyzer) calculateStatistics(result *AnalysisResult) {
	if result.TotalProcesses == 0 {
		return
	}

	// Tính average children
	totalChildren := 0
	for _, count := range result.ProcessStatistics.MostCommonExecutables {
		totalChildren += count
	}
	result.ProcessStatistics.AverageChildren = float64(totalChildren) / float64(result.TotalProcesses)

	// Tìm max children
	for _, count := range result.ProcessStatistics.MostCommonExecutables {
		if count > result.ProcessStatistics.MaxChildren {
			result.ProcessStatistics.MaxChildren = count
		}
	}
}

// findSuspiciousChains tìm các chuỗi process đáng ngờ
func (a *ProcessTreeAnalyzer) findSuspiciousChains(result *AnalysisResult) {
	// Tìm các chuỗi process liên tiếp đáng ngờ
	// Logic này có thể được mở rộng để tìm patterns phức tạp hơn

	// Ví dụ: tìm chuỗi PowerShell -> cmd -> wmic
	suspiciousPatterns := []struct {
		pattern     []string
		description string
		riskLevel   string
	}{
		{
			pattern:     []string{"powershell.exe", "cmd.exe"},
			description: "PowerShell spawning command prompt",
			riskLevel:   "medium",
		},
		{
			pattern:     []string{"cmd.exe", "wmic.exe"},
			description: "Command prompt spawning WMIC",
			riskLevel:   "high",
		},
		{
			pattern:     []string{"powershell.exe", "certutil.exe"},
			description: "PowerShell spawning certutil",
			riskLevel:   "high",
		},
	}

	for _, pattern := range suspiciousPatterns {
		// Tìm các chuỗi process phù hợp với pattern
		// Logic này cần được implement dựa trên cấu trúc tree
		_ = pattern // Placeholder
	}
}

// findAnomalies tìm các bất thường trong process tree
func (a *ProcessTreeAnalyzer) findAnomalies(result *AnalysisResult) {
	// Tìm processes có quá nhiều con
	for executable, count := range result.ProcessStatistics.MostCommonExecutables {
		if count > 20 { // Threshold có thể điều chỉnh
			result.Anomalies = append(result.Anomalies, Anomaly{
				Type:        "excessive_children",
				Severity:    "medium",
				Description: fmt.Sprintf("Process %s has %d children", executable, count),
				Timestamp:   time.Now().UTC(),
				Details: map[string]interface{}{
					"executable": executable,
					"count":      count,
				},
			})
		}
	}

	// Tìm processes có thời gian sống bất thường
	// Logic này cần được implement dựa trên dữ liệu thực tế

	// Tìm processes không có parent (orphan processes)
	if result.OrphanProcesses > 0 {
		result.Anomalies = append(result.Anomalies, Anomaly{
			Type:        "orphan_processes",
			Severity:    "low",
			Description: fmt.Sprintf("Found %d orphan processes", result.OrphanProcesses),
			Timestamp:   time.Now().UTC(),
			Details: map[string]interface{}{
				"count": result.OrphanProcesses,
			},
		})
	}
}

// GetTopSuspiciousProcesses trả về danh sách process đáng ngờ nhất
func (a *ProcessTreeAnalyzer) GetTopSuspiciousProcesses(result *AnalysisResult, limit int) []ProcessInfo {
	// Sắp xếp theo mức độ đáng ngờ
	suspiciousProcesses := []ProcessInfo{}

	// Logic để tìm và sắp xếp processes đáng ngờ
	// Có thể dựa trên:
	// - Tần suất xuất hiện
	// - Thời gian sống
	// - Số lượng con
	// - Patterns đáng ngờ

	return suspiciousProcesses
}

// GenerateReport tạo báo cáo phân tích
func (a *ProcessTreeAnalyzer) GenerateReport(result *AnalysisResult) string {
	var report strings.Builder

	report.WriteString(fmt.Sprintf("Process Tree Analysis Report\n"))
	report.WriteString(fmt.Sprintf("Endpoint: %s\n", result.EndpointID))
	report.WriteString(fmt.Sprintf("Analysis Time: %s\n", result.AnalysisTimestamp.Format(time.RFC3339)))
	report.WriteString(fmt.Sprintf("Total Processes: %d\n", result.TotalProcesses))
	report.WriteString(fmt.Sprintf("Suspicious Processes: %d\n", result.SuspiciousProcesses))
	report.WriteString(fmt.Sprintf("Tree Depth: %d\n", result.TreeDepth))
	report.WriteString(fmt.Sprintf("Root Processes: %d\n", result.RootProcesses))
	report.WriteString(fmt.Sprintf("Orphan Processes: %d\n", result.OrphanProcesses))

	report.WriteString(fmt.Sprintf("\nSuspicious Chains: %d\n", len(result.SuspiciousChains)))
	for i, chain := range result.SuspiciousChains {
		report.WriteString(fmt.Sprintf("  %d. %s (Risk: %s, Count: %d)\n",
			i+1, chain.Description, chain.RiskLevel, chain.ProcessCount))
	}

	report.WriteString(fmt.Sprintf("\nAnomalies: %d\n", len(result.Anomalies)))
	for i, anomaly := range result.Anomalies {
		report.WriteString(fmt.Sprintf("  %d. [%s] %s: %s\n",
			i+1, anomaly.Severity, anomaly.Type, anomaly.Description))
	}

	return report.String()
}
