package scanner

import "time"

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a single vulnerability or issue found
type Finding struct {
	ID          string
	Layer       string   // "network", "webapp", "llm"
	Title       string
	Description string
	Severity    Severity
	Reference   string   // OWASP / CVE reference
	Evidence    string   // What was observed
	Remediation string
}

// AttackChain represents a correlated cross-layer attack scenario.
// Chains are detected by combining findings from multiple layers.
type AttackChain struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Severity    Severity   `json:"severity"`
	FindingIDs  []string   `json:"finding_ids"`
	LayerNames  []string   `json:"layers"`
	Description string     `json:"description"` // 1-sentence attack scenario
}

// LayerResult holds results from one scanning layer
type LayerResult struct {
	Layer    string
	Target   string
	Duration time.Duration
	Findings []Finding
	Errors   []string
}

// ScanResult is the complete output of a full scan
type ScanResult struct {
	Target       string
	StartTime    time.Time
	EndTime      time.Time
	Layers       []LayerResult
	AttackChains []AttackChain
}

// TotalFindings returns count by severity
func (r *ScanResult) TotalFindings() map[Severity]int {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}
	for _, layer := range r.Layers {
		for _, f := range layer.Findings {
			counts[f.Severity]++
		}
	}
	return counts
}

// Scanner is the interface each layer must implement
type Scanner interface {
	Name() string
	Scan(target string, timeoutSec int) (*LayerResult, error)
}
