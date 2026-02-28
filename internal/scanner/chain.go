package scanner

import (
	"fmt"
	"strings"
)

// chainCondition is one required component of an attack chain.
// A finding must match both layer and have an ID that starts with idPrefix.
type chainCondition struct {
	layer    string
	idPrefix string // e.g. "LLM01", "WEB-020", "LLM07"
}

type chainTemplate struct {
	title       string
	severity    Severity
	description string
	conditions  []chainCondition // all conditions must be satisfied
}

// chainTemplates defines detectable cross-layer attack scenarios.
var chainTemplates = []chainTemplate{
	{
		title:       "Unauthenticated prompt injection with system prompt leakage",
		severity:    SeverityCritical,
		description: "An attacker can inject prompts to override model behavior AND exfiltrate the system prompt, exposing internal configuration and secrets.",
		conditions: []chainCondition{
			{layer: "llm", idPrefix: "LLM01"},
			{layer: "llm", idPrefix: "LLM07"},
		},
	},
	{
		title:       "Cross-origin credential exfiltration via CORS + LLM data disclosure",
		severity:    SeverityCritical,
		description: "Reflected CORS with credentials allows any website to exfiltrate sensitive data returned by the LLM API.",
		conditions: []chainCondition{
			{layer: "webapp", idPrefix: "WEB-020"},
			{layer: "llm", idPrefix: "LLM02"},
		},
	},
	{
		title:       "Prompt injection with tool abuse via excessive agency",
		severity:    SeverityHigh,
		description: "An attacker can inject prompts to hijack the LLM's exposed internal tools, potentially causing unauthorized code execution or data access.",
		conditions: []chainCondition{
			{layer: "llm", idPrefix: "LLM01"},
			{layer: "llm", idPrefix: "LLM06"},
		},
	},
	{
		title:       "Cleartext LLM API with prompt injection",
		severity:    SeverityHigh,
		description: "The LLM endpoint is accessible over unencrypted HTTP and is vulnerable to prompt injection; a network attacker can intercept and manipulate all traffic.",
		conditions: []chainCondition{
			{layer: "llm", idPrefix: "LLM01"},
			{layer: "network", idPrefix: "NET-"},
		},
	},
}

// findingsIndex maps (layer, idPrefix) to the first matching finding.
type findingsIndex map[string][]Finding // key: "layer:prefix"

// DetectChains analyzes a ScanResult and returns cross-layer attack chains.
func DetectChains(result *ScanResult) []AttackChain {
	// Index findings by layer+idPrefix for fast lookup
	idx := make(findingsIndex)
	for _, lr := range result.Layers {
		for _, f := range lr.Findings {
			for _, tmpl := range chainTemplates {
				for _, cond := range tmpl.conditions {
					if strings.EqualFold(f.Layer, cond.layer) && strings.HasPrefix(f.ID, cond.idPrefix) {
						k := cond.layer + ":" + cond.idPrefix
						idx[k] = append(idx[k], f)
					}
				}
			}
		}
	}

	var chains []AttackChain
	for i, tmpl := range chainTemplates {
		var findingIDs []string
		var layerNames []string
		matched := true

		for _, cond := range tmpl.conditions {
			k := cond.layer + ":" + cond.idPrefix
			fs, ok := idx[k]
			if !ok {
				matched = false
				break
			}
			// Take the first matching finding for the chain
			findingIDs = append(findingIDs, fs[0].ID)
			// Track unique layer names
			if !containsStr(layerNames, cond.layer) {
				layerNames = append(layerNames, cond.layer)
			}
		}

		if matched {
			chains = append(chains, AttackChain{
				ID:          fmt.Sprintf("CHAIN-%03d", i+1),
				Title:       tmpl.title,
				Severity:    tmpl.severity,
				FindingIDs:  findingIDs,
				LayerNames:  layerNames,
				Description: tmpl.description,
			})
		}
	}

	return chains
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
