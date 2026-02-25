package config

// ScanConfig holds all scan parameters
type ScanConfig struct {
	Target      string
	Layers      []string // "network", "webapp", "llm"
	OutputFormat string   // "terminal", "json", "markdown", "html"
	OutputFile  string
	Timeout     int // seconds
	Verbose     bool
	LLMAPIKey   string // optional, for LLM endpoint testing
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *ScanConfig {
	return &ScanConfig{
		Layers:       []string{"network", "webapp", "llm"},
		OutputFormat: "terminal",
		Timeout:      10,
	}
}
