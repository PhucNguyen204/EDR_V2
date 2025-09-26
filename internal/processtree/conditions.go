package processtree

import (
	"regexp"
	"strings"
	"time"
)

// ProcessTreeConditions định nghĩa các điều kiện để xây dựng process tree
type ProcessTreeConditions struct {
	// Điều kiện cơ bản
	MinProcessLifetime time.Duration // Thời gian tối thiểu process phải sống
	MaxTreeDepth       int           // Độ sâu tối đa của cây
	MaxChildrenPerNode int           // Số con tối đa mỗi node

	// Điều kiện lọc process
	ExcludeSystemProcesses bool     // Loại bỏ system processes
	ExcludePatterns        []string // Patterns để loại bỏ (regex)
	IncludeOnlyPatterns    []string // Chỉ bao gồm patterns này (regex)

	// Điều kiện suspicious behavior
	DetectSuspiciousProcesses bool     // Phát hiện process đáng ngờ
	SuspiciousPatterns        []string // Patterns đáng ngờ (regex)
	SuspiciousExecutables     []string // Executables đáng ngờ

	// Điều kiện correlation
	EnableCorrelation     bool          // Bật correlation với detections
	CorrelationTimeWindow time.Duration // Time window cho correlation
	MinCorrelationCount   int           // Số lượng correlation tối thiểu
}

// DefaultProcessTreeConditions trả về điều kiện mặc định
func DefaultProcessTreeConditions() *ProcessTreeConditions {
	return &ProcessTreeConditions{
		MinProcessLifetime:     5 * time.Second,
		MaxTreeDepth:           10,
		MaxChildrenPerNode:     50,
		ExcludeSystemProcesses: true,
		ExcludePatterns: []string{
			`(?i)system`,
			`(?i)svchost\.exe`,
			`(?i)winlogon\.exe`,
			`(?i)csrss\.exe`,
			`(?i)smss\.exe`,
			`(?i)wininit\.exe`,
			`(?i)services\.exe`,
			`(?i)lsass\.exe`,
			`(?i)explorer\.exe`,
			`(?i)dwm\.exe`,
		},
		IncludeOnlyPatterns:       []string{},
		DetectSuspiciousProcesses: true,
		SuspiciousPatterns: []string{
			`(?i)powershell`,
			`(?i)cmd\.exe`,
			`(?i)wmic\.exe`,
			`(?i)certutil\.exe`,
			`(?i)rundll32\.exe`,
			`(?i)regsvr32\.exe`,
			`(?i)mshta\.exe`,
			`(?i)schtasks\.exe`,
			`(?i)sc\.exe`,
			`(?i)net\.exe`,
			`(?i)at\.exe`,
			`(?i)bitsadmin\.exe`,
			`(?i)wget\.exe`,
			`(?i)curl\.exe`,
			`(?i)ftp\.exe`,
			`(?i)telnet\.exe`,
		},
		SuspiciousExecutables: []string{
			"powershell.exe",
			"cmd.exe",
			"wmic.exe",
			"certutil.exe",
			"rundll32.exe",
			"regsvr32.exe",
			"mshta.exe",
			"schtasks.exe",
			"sc.exe",
			"net.exe",
			"at.exe",
			"bitsadmin.exe",
			"wget.exe",
			"curl.exe",
			"ftp.exe",
			"telnet.exe",
		},
		EnableCorrelation:     true,
		CorrelationTimeWindow: 5 * time.Minute,
		MinCorrelationCount:   3,
	}
}

// ShouldIncludeProcess kiểm tra xem process có nên được bao gồm trong tree không
func (c *ProcessTreeConditions) ShouldIncludeProcess(event Event) bool {
	// Kiểm tra thời gian sống tối thiểu
	if time.Since(event.Timestamp) < c.MinProcessLifetime {
		return false
	}

	// Kiểm tra system processes
	if c.ExcludeSystemProcesses && c.isSystemProcess(event) {
		return false
	}

	// Kiểm tra exclude patterns
	for _, pattern := range c.ExcludePatterns {
		if matched, _ := regexp.MatchString(pattern, event.Executable); matched {
			return false
		}
		if matched, _ := regexp.MatchString(pattern, event.CommandLine); matched {
			return false
		}
	}

	// Kiểm tra include patterns (nếu có)
	if len(c.IncludeOnlyPatterns) > 0 {
		include := false
		for _, pattern := range c.IncludeOnlyPatterns {
			if matched, _ := regexp.MatchString(pattern, event.Executable); matched {
				include = true
				break
			}
			if matched, _ := regexp.MatchString(pattern, event.CommandLine); matched {
				include = true
				break
			}
		}
		if !include {
			return false
		}
	}

	return true
}

// IsSuspiciousProcess kiểm tra xem process có đáng ngờ không
func (c *ProcessTreeConditions) IsSuspiciousProcess(event Event) bool {
	if !c.DetectSuspiciousProcesses {
		return false
	}

	// Kiểm tra suspicious patterns
	for _, pattern := range c.SuspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, event.Executable); matched {
			return true
		}
		if matched, _ := regexp.MatchString(pattern, event.CommandLine); matched {
			return true
		}
	}

	// Kiểm tra suspicious executables
	executable := strings.ToLower(event.Executable)
	for _, suspicious := range c.SuspiciousExecutables {
		if strings.Contains(executable, strings.ToLower(suspicious)) {
			return true
		}
	}

	return false
}

// isSystemProcess kiểm tra xem process có phải system process không
func (c *ProcessTreeConditions) isSystemProcess(event Event) bool {
	systemProcesses := []string{
		"system",
		"svchost.exe",
		"winlogon.exe",
		"csrss.exe",
		"smss.exe",
		"wininit.exe",
		"services.exe",
		"lsass.exe",
		"explorer.exe",
		"dwm.exe",
		"conhost.exe",
		"audiodg.exe",
		"spoolsv.exe",
		"taskhost.exe",
		"taskhostw.exe",
		"winlogon.exe",
		"winlogon.exe",
	}

	executable := strings.ToLower(event.Executable)
	for _, sysProc := range systemProcesses {
		if strings.Contains(executable, strings.ToLower(sysProc)) {
			return true
		}
	}

	return false
}

// ValidateTreeDepth kiểm tra độ sâu của cây
func (c *ProcessTreeConditions) ValidateTreeDepth(node *Node, currentDepth int) bool {
	if currentDepth >= c.MaxTreeDepth {
		return false
	}

	if len(node.Children) > c.MaxChildrenPerNode {
		return false
	}

	return true
}
