package dag

import (
	"crypto/md5"
	"fmt"
	"log"
	"sync"
	"time"

	ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// CorrelationEvent represents an event that can be used for correlation
type CorrelationEvent struct {
	Event     any       `json:"event"`
	Time      time.Time `json:"time"`
	RuleNames []string  `json:"rule_names"`
}

// TimeWindow represents a sliding time window for correlation
type TimeWindow struct {
	Start    time.Time          `json:"start"`
	Events   []CorrelationEvent `json:"events"`
	Count    int                `json:"count"`
	GroupKey string             `json:"group_key"`
	RuleName string             `json:"rule_name"`
}

// CorrelationEngine handles correlation rules with time windows
type CorrelationEngine struct {
	rules         []ir.CompiledCorrelationRule
	windows       map[string]*TimeWindow
	mutex         sync.RWMutex
	cleanupTicker *time.Ticker
	stopChan      chan bool
	ruleNameMap   map[string]ir.RuleId // rule name -> rule ID mapping
}

// NewCorrelationEngine creates a new correlation engine
func NewCorrelationEngine(correlationRules []ir.CompiledCorrelationRule) *CorrelationEngine {
	ce := &CorrelationEngine{
		rules:       correlationRules,
		windows:     make(map[string]*TimeWindow),
		stopChan:    make(chan bool),
		ruleNameMap: make(map[string]ir.RuleId),
	}

	// Start cleanup routine
	ce.startCleanupRoutine()

	return ce
}

// SetRuleMetadata sets the rule name to rule ID mapping
func (ce *CorrelationEngine) SetRuleMetadata(ruleNameMap map[string]ir.RuleId) {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()
	ce.ruleNameMap = ruleNameMap
}

// ProcessEvent processes an event for correlation
func (ce *CorrelationEngine) ProcessEvent(event any, matchedRules []ir.RuleId) []CorrelationAlert {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	// No debug logging - only log when correlation condition is met
	var alerts []CorrelationAlert

	for _, corrRule := range ce.rules {
		// Check if any of the matched rules match the correlation rule's referenced rules
		if !ce.matchedRulesContainReferencedRules(matchedRules, corrRule.Rules) {
			continue
		}

		// Create group key from group-by fields
		groupKey := ce.createGroupKey(event, corrRule.GroupBy, corrRule.Name)

		// Get or create time window
		window := ce.getOrCreateWindow(groupKey, corrRule.Timespan, corrRule.Name)

		// Add event to window
		correlationEvent := CorrelationEvent{
			Event:     event,
			Time:      time.Now(),
			RuleNames: corrRule.Rules,
		}
		window.Events = append(window.Events, correlationEvent)
		window.Count++

		// No debug logging for adding events to windows

		// Check correlation condition
		if ce.checkCorrelationCondition(window, corrRule) {
			log.Printf("CORRELATION ALERT: Rule %s triggered with count %d (threshold: %d)", corrRule.Name, window.Count, corrRule.ValueCount.Gte)
			alert := CorrelationAlert{
				Rule:      corrRule,
				Window:    *window,
				Timestamp: time.Now(),
			}
			alerts = append(alerts, alert)

			// Reset window after alert
			ce.resetWindow(groupKey)
		}
	}

	return alerts
}

// matchedRulesContainReferencedRules checks if any matched rule IDs correspond to the referenced rule names
func (ce *CorrelationEngine) matchedRulesContainReferencedRules(matchedRules []ir.RuleId, referencedRuleNames []string) bool {
	for _, ruleName := range referencedRuleNames {
		if ruleID, exists := ce.ruleNameMap[ruleName]; exists {
			for _, matchedRuleID := range matchedRules {
				if matchedRuleID == ruleID {
					// No debug logging - just return match
					return true
				}
			}
		}
	}
	return false
}

// eventMatchesCorrelationRules checks if event matches any of the referenced rules
func (ce *CorrelationEngine) eventMatchesCorrelationRules(event any, ruleNames []string) bool {
	log.Printf("DEBUG: eventMatchesCorrelationRules called with ruleNames: %v", ruleNames)

	eventMap, ok := event.(map[string]any)
	if !ok {
		log.Printf("DEBUG: event is not a map[string]any")
		return false
	}

	// For each referenced rule name, check if the event matches that specific rule
	for _, ruleName := range ruleNames {
		if ce.eventMatchesSpecificRule(eventMap, ruleName) {
			log.Printf("DEBUG: Event matches rule %s, returning true", ruleName)
			return true
		}
	}

	log.Printf("DEBUG: No matching rules found, returning false")
	return false
}

// eventMatchesSpecificRule checks if event matches a specific rule based on rule name
func (ce *CorrelationEngine) eventMatchesSpecificRule(eventMap map[string]any, ruleName string) bool {
	switch ruleName {
	case "bruteforce_openssh_vaild_users":
		// Check for SSH brute-force with valid users (EventID 4625, SubStatus 0xc000006A, ProcessName sshd.exe)
		if eventID, exists := eventMap["EventID"]; exists && eventID == 4625 {
			if subStatus, exists := eventMap["SubStatus"]; exists && subStatus == "0xc000006A" {
				if processName, exists := eventMap["ProcessName"]; exists {
					if processNameStr, ok := processName.(string); ok {
						if processNameStr == "C:\\Windows\\System32\\sshd.exe" ||
							processNameStr == "C:\\Program Files\\OpenSSH-Win64\\sshd.exe" ||
							processNameStr == "sshd.exe" {
							return true
						}
					}
				}
			}
		}

	case "login_non_existing_user":
		// Check for login attempts with non-existing users (EventID 4625, SubStatus 0xc0000064)
		if eventID, exists := eventMap["EventID"]; exists && eventID == 4625 {
			if subStatus, exists := eventMap["SubStatus"]; exists && subStatus == "0xc0000064" {
				return true
			}
		}

	case "bruteforce_denied_account_restriction_policies":
		// Check for account restriction failures (EventID 4625, Status in specific list)
		if eventID, exists := eventMap["EventID"]; exists && eventID == 4625 {
			if status, exists := eventMap["Status"]; exists {
				statusStr, ok := status.(string)
				if ok {
					restrictionStatuses := []string{
						"0xc0000022", "0xC0000413", "0xC000006E",
						"0xC000006F", "0xC0000070", "0xC000015B",
					}
					for _, restrictionStatus := range restrictionStatuses {
						if statusStr == restrictionStatus {
							return true
						}
					}
				}
			}
		}

	default:
		// For other rules, use generic matching
		log.Printf("DEBUG: Unknown rule name %s, using generic matching", ruleName)
		if eventID, exists := eventMap["EventID"]; exists && eventID == 4625 {
			return true
		}
	}

	return false
}

// createGroupKey creates a unique key for grouping events
func (ce *CorrelationEngine) createGroupKey(event any, groupBy []string, ruleName string) string {
	eventMap, ok := event.(map[string]any)
	if !ok {
		return fmt.Sprintf("%s:default", ruleName)
	}

	var keyParts []string
	keyParts = append(keyParts, ruleName)

	for _, field := range groupBy {
		if value, exists := eventMap[field]; exists {
			keyParts = append(keyParts, fmt.Sprintf("%s:%v", field, value))
		}
	}

	// Create hash for uniqueness
	keyStr := fmt.Sprintf("%v", keyParts)
	hash := md5.Sum([]byte(keyStr))
	return fmt.Sprintf("%x", hash)
}

// getOrCreateWindow gets or creates a time window for the given key
func (ce *CorrelationEngine) getOrCreateWindow(groupKey string, timespan time.Duration, ruleName string) *TimeWindow {
	if window, exists := ce.windows[groupKey]; exists {
		// Check if window is still valid
		if time.Since(window.Start) <= timespan {
			return window
		}
		// Window expired, reset it
		ce.resetWindow(groupKey)
	}

	// Create new window
	window := &TimeWindow{
		Start:    time.Now(),
		Events:   make([]CorrelationEvent, 0),
		Count:    0,
		GroupKey: groupKey,
		RuleName: ruleName,
	}
	ce.windows[groupKey] = window

	return window
}

// checkCorrelationCondition checks if the correlation condition is met
func (ce *CorrelationEngine) checkCorrelationCondition(window *TimeWindow, rule ir.CompiledCorrelationRule) bool {
	if rule.ValueCount == nil {
		return false
	}

	// Check if count meets the threshold
	return window.Count >= rule.ValueCount.Gte
}

// resetWindow resets a time window
func (ce *CorrelationEngine) resetWindow(groupKey string) {
	if window, exists := ce.windows[groupKey]; exists {
		window.Start = time.Now()
		window.Events = make([]CorrelationEvent, 0)
		window.Count = 0
	}
}

// startCleanupRoutine starts the cleanup routine for expired windows
func (ce *CorrelationEngine) startCleanupRoutine() {
	ce.cleanupTicker = time.NewTicker(5 * time.Minute)
	go func() {
		for {
			select {
			case <-ce.cleanupTicker.C:
				ce.cleanupExpiredWindows()
			case <-ce.stopChan:
				ce.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// cleanupExpiredWindows removes expired time windows
func (ce *CorrelationEngine) cleanupExpiredWindows() {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	now := time.Now()
	maxAge := 1 * time.Hour // Keep windows for max 1 hour

	for key, window := range ce.windows {
		if now.Sub(window.Start) > maxAge {
			delete(ce.windows, key)
		}
	}
}

// Stop stops the correlation engine
func (ce *CorrelationEngine) Stop() {
	ce.stopChan <- true
}

// GetWindowCount returns the number of active windows
func (ce *CorrelationEngine) GetWindowCount() int {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()
	return len(ce.windows)
}

// GetWindowStats returns statistics about active windows
func (ce *CorrelationEngine) GetWindowStats() map[string]int {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()

	stats := make(map[string]int)
	for _, window := range ce.windows {
		stats[window.RuleName]++
	}
	return stats
}

// CorrelationAlert represents a correlation alert
type CorrelationAlert struct {
	Rule      ir.CompiledCorrelationRule `json:"rule"`
	Window    TimeWindow                 `json:"window"`
	Timestamp time.Time                  `json:"timestamp"`
}
