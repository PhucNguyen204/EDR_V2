package dag

import (
	"fmt"
	"log"
	"sync"
	"time"

	ir "github.com/PhucNguyen204/EDR_V2/engine_sigma_by_golang"
)

// BatchProcessor handles batch processing of events for correlation analysis
type BatchProcessor struct {
	engine            *DagEngine
	correlationEngine *CorrelationEngine
	ruleNameMap       map[string]ir.RuleId // rule name -> rule ID mapping
	ruleIDMap         map[ir.RuleId]string // rule ID -> rule name mapping
	mu                sync.RWMutex
}

// BatchResult contains the results of processing a batch of events
type BatchResult struct {
	ProcessedEvents   int                    `json:"processed_events"`
	MatchedRules      map[string][]ir.RuleId `json:"matched_rules"` // rule name -> matched rule IDs
	CorrelationAlerts []CorrelationAlert     `json:"correlation_alerts"`
	ProcessingTime    time.Duration          `json:"processing_time"`
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(engine *DagEngine) *BatchProcessor {
	bp := &BatchProcessor{
		engine:            engine,
		correlationEngine: engine.correlationEngine,
		ruleNameMap:       make(map[string]ir.RuleId),
		ruleIDMap:         make(map[ir.RuleId]string),
	}

	// Note: Rule metadata will be populated when ruleset is available
	// For now, we'll build mappings dynamically during processing

	return bp
}

// ProcessBatch processes a batch of events and returns correlation results
func (bp *BatchProcessor) ProcessBatch(events []any) (*BatchResult, error) {
	start := time.Now()
	bp.mu.Lock()
	defer bp.mu.Unlock()

	result := &BatchResult{
		ProcessedEvents:   len(events),
		MatchedRules:      make(map[string][]ir.RuleId),
		CorrelationAlerts: make([]CorrelationAlert, 0),
	}

	log.Printf("DEBUG: BatchProcessor processing %d events", len(events))

	// Step 1: Process each event individually to get matched rules
	eventRuleMatches := make(map[string][]ir.RuleId) // event key -> matched rule IDs
	eventData := make(map[string]any)                // event key -> event data

	for i, event := range events {
		eventKey := fmt.Sprintf("event_%d", i)
		eventData[eventKey] = event

		// Evaluate single event
		evalResult, err := bp.engine.Evaluate(event)
		if err != nil {
			log.Printf("DEBUG: Error evaluating event %d: %v", i, err)
			continue
		}

		if len(evalResult.MatchedRules) > 0 {
			eventRuleMatches[eventKey] = evalResult.MatchedRules
			log.Printf("DEBUG: Event %d matched %d rules: %v", i, len(evalResult.MatchedRules), evalResult.MatchedRules)

			// Group by rule names for batch analysis
			for _, ruleID := range evalResult.MatchedRules {
				ruleName := bp.getRuleNameByID(ruleID)
				if ruleName != "" {
					result.MatchedRules[ruleName] = append(result.MatchedRules[ruleName], ruleID)
				}
			}
		}
	}

	// Step 2: Check correlation rules for each matched rule name
	if bp.correlationEngine != nil {
		log.Printf("DEBUG: Checking correlation rules for %d rule names", len(result.MatchedRules))

		for ruleName, ruleIDs := range result.MatchedRules {
			log.Printf("DEBUG: Processing correlation for rule: %s (matched %d times)", ruleName, len(ruleIDs))

			// Find correlation rules that reference this rule name
			correlationRules := bp.findCorrelationRulesForRule(ruleName)
			if len(correlationRules) == 0 {
				log.Printf("DEBUG: No correlation rules found for rule: %s", ruleName)
				continue
			}

			// Process correlation for each correlation rule
			for _, corrRule := range correlationRules {
				log.Printf("DEBUG: Processing correlation rule: %s (type: %s)", corrRule.Name, corrRule.Type)

				// Get events that matched this rule
				matchingEvents := bp.getEventsForRule(events, ruleName, eventRuleMatches, eventData)

				// Process correlation
				alerts := bp.processCorrelationForRule(corrRule, matchingEvents, ruleName)
				result.CorrelationAlerts = append(result.CorrelationAlerts, alerts...)

				log.Printf("DEBUG: Correlation rule %s generated %d alerts", corrRule.Name, len(alerts))
			}
		}
	}

	result.ProcessingTime = time.Since(start)
	log.Printf("DEBUG: BatchProcessor completed in %v, generated %d correlation alerts",
		result.ProcessingTime, len(result.CorrelationAlerts))

	return result, nil
}

// getRuleNameByID gets rule name by rule ID
func (bp *BatchProcessor) getRuleNameByID(ruleID ir.RuleId) string {
	if name, exists := bp.ruleIDMap[ruleID]; exists {
		return name
	}
	// Try to get from server's rule metadata if available
	// For now, return empty string
	return ""
}

// findCorrelationRulesForRule finds correlation rules that reference the given rule name
func (bp *BatchProcessor) findCorrelationRulesForRule(ruleName string) []ir.CompiledCorrelationRule {
	var matchingRules []ir.CompiledCorrelationRule

	if bp.correlationEngine != nil {
		for _, corrRule := range bp.correlationEngine.rules {
			for _, refRule := range corrRule.Rules {
				if refRule == ruleName {
					matchingRules = append(matchingRules, corrRule)
					break
				}
			}
		}
	}

	return matchingRules
}

// getEventsForRule gets events that matched the specified rule
func (bp *BatchProcessor) getEventsForRule(events []any, ruleName string, eventRuleMatches map[string][]ir.RuleId, eventData map[string]any) []any {
	var matchingEvents []any

	for eventKey, matchedRuleIDs := range eventRuleMatches {
		// Check if this event matched the rule we're looking for
		ruleID := bp.ruleNameMap[ruleName]
		for _, matchedID := range matchedRuleIDs {
			if matchedID == ruleID {
				if event, exists := eventData[eventKey]; exists {
					matchingEvents = append(matchingEvents, event)
				}
				break
			}
		}
	}

	return matchingEvents
}

// processCorrelationForRule processes correlation for a specific rule and its matching events
func (bp *BatchProcessor) processCorrelationForRule(corrRule ir.CompiledCorrelationRule, events []any, ruleName string) []CorrelationAlert {
	var alerts []CorrelationAlert

	if len(events) == 0 {
		return alerts
	}

	log.Printf("DEBUG: Processing correlation for rule %s with %d matching events", ruleName, len(events))

	// Group events by correlation group-by fields
	groupedEvents := bp.groupEventsByCorrelationFields(events, corrRule.GroupBy)

	// Check correlation conditions for each group
	for groupKey, groupEvents := range groupedEvents {
		log.Printf("DEBUG: Checking correlation condition for group %s with %d events", groupKey, len(groupEvents))

		// Create time window for this group
		window := &TimeWindow{
			Start:    time.Now(),
			Events:   make([]CorrelationEvent, 0),
			Count:    len(groupEvents),
			GroupKey: groupKey,
			RuleName: corrRule.Name,
		}

		// Add events to window
		for _, event := range groupEvents {
			window.Events = append(window.Events, CorrelationEvent{
				Event:     event,
				Time:      time.Now(),
				RuleNames: []string{ruleName},
			})
		}

		// Check correlation condition
		if bp.checkCorrelationCondition(window, &corrRule) {
			alert := CorrelationAlert{
				Rule:      corrRule,
				Window:    *window,
				Timestamp: time.Now(),
			}
			alerts = append(alerts, alert)
			log.Printf("DEBUG: Correlation alert triggered for rule %s, group %s, count %d",
				corrRule.Name, groupKey, window.Count)
		}
	}

	return alerts
}

// groupEventsByCorrelationFields groups events by correlation group-by fields
func (bp *BatchProcessor) groupEventsByCorrelationFields(events []any, groupByFields []string) map[string][]any {
	groups := make(map[string][]any)

	for _, event := range events {
		groupKey := bp.createGroupKey(event, groupByFields, "batch")
		groups[groupKey] = append(groups[groupKey], event)
	}

	return groups
}

// createGroupKey creates a group key from event and group-by fields
func (bp *BatchProcessor) createGroupKey(event any, groupByFields []string, ruleName string) string {
	eventMap, ok := event.(map[string]any)
	if !ok {
		return fmt.Sprintf("%s:default", ruleName)
	}

	var keyParts []string
	keyParts = append(keyParts, ruleName)

	for _, field := range groupByFields {
		if value, exists := eventMap[field]; exists {
			keyParts = append(keyParts, fmt.Sprintf("%s:%v", field, value))
		} else {
			keyParts = append(keyParts, fmt.Sprintf("%s:N/A", field))
		}
	}

	keyStr := fmt.Sprintf("%v", keyParts)
	return keyStr
}

// checkCorrelationCondition checks if correlation condition is met
func (bp *BatchProcessor) checkCorrelationCondition(window *TimeWindow, rule *ir.CompiledCorrelationRule) bool {
	if rule.ValueCount == nil {
		return false
	}

	// Check if count meets the threshold
	return window.Count >= rule.ValueCount.Gte
}

// SetRuleMetadata sets rule name mappings from server metadata
func (bp *BatchProcessor) SetRuleMetadata(ruleMeta map[uint32]string) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.ruleNameMap = make(map[string]ir.RuleId)
	bp.ruleIDMap = make(map[ir.RuleId]string)

	for ruleID, ruleName := range ruleMeta {
		bp.ruleNameMap[ruleName] = ir.RuleId(ruleID)
		bp.ruleIDMap[ir.RuleId(ruleID)] = ruleName
	}

	log.Printf("DEBUG: BatchProcessor set %d rule mappings", len(ruleMeta))
}

// GetBatchStats returns statistics about batch processing
func (bp *BatchProcessor) GetBatchStats() map[string]interface{} {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	stats := map[string]interface{}{
		"rule_name_mappings":     len(bp.ruleNameMap),
		"has_correlation_engine": bp.correlationEngine != nil,
	}

	if bp.correlationEngine != nil {
		stats["correlation_rules"] = len(bp.correlationEngine.rules)
		stats["active_windows"] = len(bp.correlationEngine.windows)
	}

	return stats
}
