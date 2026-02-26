package webapp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/onoz1169/1scan/internal/scanner"
)

// NucleiEnricher runs nuclei as an optional subprocess and parses JSONL output.
type NucleiEnricher struct {
	binaryPath string
	templates  string
	timeout    time.Duration
}

func newNucleiEnricher(binaryPath, templates string, timeout time.Duration) *NucleiEnricher {
	return &NucleiEnricher{
		binaryPath: binaryPath,
		templates:  templates,
		timeout:    timeout,
	}
}

type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	MatchedAt   string `json:"matched-at"`
	MatcherName string `json:"matcher-name"`
}

func mapNucleiSeverity(s string) scanner.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return scanner.SeverityCritical
	case "high":
		return scanner.SeverityHigh
	case "medium":
		return scanner.SeverityMedium
	case "low":
		return scanner.SeverityLow
	default:
		return scanner.SeverityInfo
	}
}

// Enrich runs nuclei against the target and returns findings.
func (n *NucleiEnricher) Enrich(target string) ([]scanner.Finding, error) {
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	defer cancel()

	args := []string{
		"-target", target,
		"-templates", n.templates,
		"-jsonl",
		"-severity", "medium,high,critical",
		"-silent",
	}

	cmd := exec.CommandContext(ctx, n.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("nuclei timed out after %s", n.timeout)
		}
		exitErr, ok := err.(*exec.ExitError)
		if ok && exitErr.ExitCode() != 0 && stdout.Len() == 0 {
			return nil, fmt.Errorf("nuclei exited with code %d: %s", exitErr.ExitCode(), stderr.String())
		}
	}

	var findings []scanner.Finding
	s := bufio.NewScanner(&stdout)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}

		var nr nucleiResult
		if err := json.Unmarshal([]byte(line), &nr); err != nil {
			continue
		}

		findings = append(findings, scanner.Finding{
			ID:          "WEB-NUC-" + nr.TemplateID,
			Title:       nr.Info.Name,
			Severity:    mapNucleiSeverity(nr.Info.Severity),
			Evidence:    "nuclei: " + nr.TemplateID + " matched at " + nr.MatchedAt,
			Reference:   "nuclei template: " + nr.TemplateID,
			Remediation: "See nuclei template documentation for remediation guidance.",
			Layer:       "webapp",
		})
	}

	return findings, nil
}
