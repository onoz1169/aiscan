# Project CLAUDE.md

## Overview
aiscan is an all-in-one security scanner CLI covering Network (port scan), Web App (OWASP Top 10), and LLM (OWASP LLM Top 10) layers. Written in Go with Cobra CLI framework.

## Architecture
3-layer scanner architecture: network, webapp, llm. Each layer implements the `scanner.Scanner` interface defined in `internal/scanner/types.go`. A report generator (`internal/report/`) handles terminal, JSON, and Markdown output. The Cobra CLI (`cmd/`) orchestrates scanning and output.

## Dev Commands
```
# build
go build -o aiscan .

# test
go test ./...

# lint
golangci-lint run

# run
./aiscan scan --target https://example.com
```

## Project-specific Rules
- All scanner layers must implement the `Scanner` interface from `internal/scanner/types.go`.
- Findings use severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO.
- Exit code 1 if any CRITICAL or HIGH findings are detected.
