package processtree

import (
	"sort"
	"sync"
	"time"
)

// Node mo ta mot tien trinh trong cay quan ly.
type Node struct {
	Key         string           `json:"key"`
	EntityID    string           `json:"entity_id,omitempty"`
	PID         string           `json:"pid,omitempty"`
	PPID        string           `json:"ppid,omitempty"`
	Name        string           `json:"name,omitempty"`
	Executable  string           `json:"executable,omitempty"`
	CommandLine string           `json:"command_line,omitempty"`
	FirstSeen   time.Time        `json:"first_seen,omitempty"`
	LastSeen    time.Time        `json:"last_seen"`
	ParentKey   string           `json:"parent_key,omitempty"`
	Children    map[string]*Node `json:"-"`
}

// TreeSnapshot la du lieu tra ve qua API.
type TreeSnapshot struct {
	Key         string         `json:"key"`
	EntityID    string         `json:"entity_id,omitempty"`
	PID         string         `json:"pid,omitempty"`
	PPID        string         `json:"ppid,omitempty"`
	Name        string         `json:"name,omitempty"`
	Executable  string         `json:"executable,omitempty"`
	CommandLine string         `json:"command_line,omitempty"`
	FirstSeen   time.Time      `json:"first_seen,omitempty"`
	LastSeen    time.Time      `json:"last_seen"`
	Children    []TreeSnapshot `json:"children,omitempty"`
}

// Event chua thong tin can thiet de cap nhat cay.
type Event struct {
	EndpointID     string
	EntityID       string
	ParentEntityID string
	PID            string
	PPID           string
	Name           string
	Executable     string
	CommandLine    string
	Timestamp      time.Time
}

type endpointTree struct {
	nodes map[string]*Node
}

// Manager dieu phoi cay tien trinh theo tung endpoint.
type Manager struct {
	mu         sync.RWMutex
	endpoints  map[string]*endpointTree
	conditions *ProcessTreeConditions
	analyzer   *ProcessTreeAnalyzer
}

// NewManager tao doi tuong quan ly moi.
func NewManager() *Manager {
	conditions := DefaultProcessTreeConditions()
	return &Manager{
		endpoints:  make(map[string]*endpointTree),
		conditions: conditions,
		analyzer:   NewProcessTreeAnalyzer(conditions),
	}
}

// NewManagerWithConditions tao manager với điều kiện tùy chỉnh.
func NewManagerWithConditions(conditions *ProcessTreeConditions) *Manager {
	return &Manager{
		endpoints:  make(map[string]*endpointTree),
		conditions: conditions,
		analyzer:   NewProcessTreeAnalyzer(conditions),
	}
}

func (m *Manager) getOrCreateEndpointTree(endpointID string) *endpointTree {
	t, ok := m.endpoints[endpointID]
	if !ok {
		t = &endpointTree{nodes: make(map[string]*Node)}
		m.endpoints[endpointID] = t
	}
	return t
}

// Upsert cap nhat cay tu su kien moi.
func (m *Manager) Upsert(evt Event) {
	if evt.EndpointID == "" {
		return
	}
	key := nodeKey(evt.EntityID, evt.PID)
	if key == "" {
		return
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}

	// Kiểm tra điều kiện trước khi thêm vào tree
	if !m.conditions.ShouldIncludeProcess(evt) {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	tree := m.getOrCreateEndpointTree(evt.EndpointID)
	node := tree.ensureNode(key)

	node.Key = key
	if evt.EntityID != "" {
		node.EntityID = evt.EntityID
	}
	if evt.PID != "" {
		node.PID = evt.PID
	}
	if evt.PPID != "" {
		node.PPID = evt.PPID
	}
	if evt.Name != "" {
		node.Name = evt.Name
	}
	if evt.Executable != "" {
		node.Executable = evt.Executable
	}
	if evt.CommandLine != "" {
		node.CommandLine = evt.CommandLine
	}
	if node.FirstSeen.IsZero() {
		node.FirstSeen = evt.Timestamp
	}
	if node.LastSeen.IsZero() || evt.Timestamp.After(node.LastSeen) {
		node.LastSeen = evt.Timestamp
	}

	parentKey := nodeKey(evt.ParentEntityID, evt.PPID)
	if parentKey != "" && parentKey != node.ParentKey {
		if node.ParentKey != "" {
			if oldParent := tree.nodes[node.ParentKey]; oldParent != nil {
				delete(oldParent.Children, node.Key)
			}
		}
		parent := tree.ensureNode(parentKey)
		if evt.ParentEntityID != "" {
			parent.EntityID = evt.ParentEntityID
		}
		if evt.PPID != "" && parent.PID == "" {
			parent.PID = evt.PPID
		}
		parent.addChild(node)
		node.ParentKey = parentKey
	} else if parentKey == "" && node.ParentKey != "" {
		if oldParent := tree.nodes[node.ParentKey]; oldParent != nil {
			delete(oldParent.Children, node.Key)
		}
		node.ParentKey = ""
	}

	// Process tree được xây dựng từ TẤT CẢ events có chứa thông tin process
	// Không cần correlation engine - chỉ cần lưu trữ và phân tích
}

func (t *endpointTree) ensureNode(key string) *Node {
	n, ok := t.nodes[key]
	if !ok {
		n = &Node{Key: key, Children: make(map[string]*Node)}
		t.nodes[key] = n
	} else if n.Children == nil {
		n.Children = make(map[string]*Node)
	}
	if n.LastSeen.IsZero() {
		n.LastSeen = time.Now().UTC()
	}
	return n
}

func (n *Node) addChild(child *Node) {
	if n.Children == nil {
		n.Children = make(map[string]*Node)
	}
	n.Children[child.Key] = child
}

func nodeKey(entityID, pid string) string {
	if entityID != "" {
		return entityID
	}
	if pid != "" {
		return "pid:" + pid
	}
	return ""
}

// Snapshot tra ve cay theo endpoint va root.
func (m *Manager) Snapshot(endpointID, rootKey string) ([]TreeSnapshot, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tree, ok := m.endpoints[endpointID]
	if !ok {
		return nil, false
	}

	if rootKey != "" {
		node, exists := tree.nodes[rootKey]
		if !exists {
			return nil, false
		}
		return []TreeSnapshot{buildSnapshot(node)}, true
	}

	roots := findRoots(tree)
	snapshots := make([]TreeSnapshot, 0, len(roots))
	for _, n := range roots {
		snapshots = append(snapshots, buildSnapshot(n))
	}
	sort.SliceStable(snapshots, func(i, j int) bool {
		return snapshots[i].LastSeen.After(snapshots[j].LastSeen)
	})
	return snapshots, true
}

func findRoots(tree *endpointTree) []*Node {
	roots := []*Node{}
	for _, node := range tree.nodes {
		if node.ParentKey == "" || tree.nodes[node.ParentKey] == nil {
			roots = append(roots, node)
		}
	}
	sort.SliceStable(roots, func(i, j int) bool {
		return roots[i].LastSeen.After(roots[j].LastSeen)
	})
	return roots
}

func buildSnapshot(node *Node) TreeSnapshot {
	snap := TreeSnapshot{
		Key:         node.Key,
		EntityID:    node.EntityID,
		PID:         node.PID,
		PPID:        node.PPID,
		Name:        node.Name,
		Executable:  node.Executable,
		CommandLine: node.CommandLine,
		FirstSeen:   node.FirstSeen,
		LastSeen:    node.LastSeen,
	}
	if len(node.Children) == 0 {
		return snap
	}
	children := make([]TreeSnapshot, 0, len(node.Children))
	keys := make([]string, 0, len(node.Children))
	for k := range node.Children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		children = append(children, buildSnapshot(node.Children[k]))
	}
	snap.Children = children
	return snap
}

// AnalyzeEndpoint phân tích process tree của một endpoint
func (m *Manager) AnalyzeEndpoint(endpointID string) (*AnalysisResult, error) {
	return m.analyzer.AnalyzeTree(m, endpointID)
}

// Process tree không cần correlation engine
// Tất cả events có chứa process info đều được xây dựng thành tree

// GetProcessTreeStats trả về thống kê tổng quan của process tree
func (m *Manager) GetProcessTreeStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"total_endpoints":      len(m.endpoints),
		"total_processes":      0,
		"suspicious_processes": 0,
		"max_tree_depth":       0,
		"endpoint_stats":       make(map[string]interface{}),
	}

	for endpointID, tree := range m.endpoints {
		endpointStats := map[string]interface{}{
			"total_processes":      len(tree.nodes),
			"suspicious_processes": 0,
			"max_depth":            0,
		}

		// Đếm suspicious processes
		for _, node := range tree.nodes {
			if m.conditions.IsSuspiciousProcess(Event{
				Executable:  node.Executable,
				CommandLine: node.CommandLine,
				Timestamp:   node.LastSeen,
			}) {
				endpointStats["suspicious_processes"] = endpointStats["suspicious_processes"].(int) + 1
			}
		}

		stats["total_processes"] = stats["total_processes"].(int) + len(tree.nodes)
		stats["suspicious_processes"] = stats["suspicious_processes"].(int) + endpointStats["suspicious_processes"].(int)
		stats["endpoint_stats"].(map[string]interface{})[endpointID] = endpointStats
	}

	return stats
}

// GetSuspiciousProcesses trả về danh sách các process đáng ngờ
func (m *Manager) GetSuspiciousProcesses(endpointID string) []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tree, exists := m.endpoints[endpointID]
	if !exists {
		return nil
	}

	var suspiciousProcesses []*Node
	for _, node := range tree.nodes {
		if m.conditions.IsSuspiciousProcess(Event{
			Executable:  node.Executable,
			CommandLine: node.CommandLine,
			Timestamp:   node.LastSeen,
		}) {
			suspiciousProcesses = append(suspiciousProcesses, node)
		}
	}

	return suspiciousProcesses
}

// GetProcessChain trả về chuỗi process từ root đến node được chỉ định
func (m *Manager) GetProcessChain(endpointID string, processKey string) []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tree, exists := m.endpoints[endpointID]
	if !exists {
		return nil
	}

	node, exists := tree.nodes[processKey]
	if !exists {
		return nil
	}

	var chain []*Node
	current := node

	// Đi ngược lên root
	for current != nil {
		chain = append([]*Node{current}, chain...)
		if current.ParentKey != "" {
			current = tree.nodes[current.ParentKey]
		} else {
			current = nil
		}
	}

	return chain
}

// GetProcessChildren trả về tất cả các con của một process
func (m *Manager) GetProcessChildren(endpointID string, processKey string) []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tree, exists := m.endpoints[endpointID]
	if !exists {
		return nil
	}

	node, exists := tree.nodes[processKey]
	if !exists {
		return nil
	}

	var children []*Node
	for _, child := range node.Children {
		children = append(children, child)
		// Đệ quy lấy các con của con
		children = append(children, m.GetProcessChildren(endpointID, child.Key)...)
	}

	return children
}
