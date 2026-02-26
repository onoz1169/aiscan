#!/bin/bash
# aiscan integration test runner
# Starts test environment, runs scans, reports results.

set -e
AISCAN=/Users/onozawa/aiscan/aiscan
TESTENV=/Users/onozawa/aiscan/testenv
RESULTS_DIR=/Users/onozawa/aiscan/testenv/results

mkdir -p "$RESULTS_DIR"

echo "=== aiscan Integration Tests ==="
echo ""

# ---- Build aiscan ----
echo "[1/5] Building aiscan..."
cd /Users/onozawa/aiscan
go build -o aiscan .
echo "  OK"

# ---- Start Docker services ----
echo "[2/5] Starting Docker services (Redis, Elasticsearch)..."
cd "$TESTENV"
docker compose up -d --wait 2>/dev/null || docker compose up -d
sleep 3
echo "  Redis:         http://localhost:6379"
echo "  Elasticsearch: http://localhost:9200"

# ---- Start vuln web server ----
echo "[3/5] Starting vulnerable web server..."
cd "$TESTENV/vuln-web"
go run main.go &
VULN_WEB_PID=$!
sleep 1
echo "  Vulnerable web: http://localhost:8080"

# ---- Start mock LLM ----
echo "[4/5] Starting mock LLM server..."
cd "$TESTENV/mock-llm"
go run main.go &
MOCK_LLM_PID=$!
sleep 1
echo "  Mock LLM:       http://localhost:11434"

echo ""
echo "=== Running Scans ==="
echo ""

# ---- Test 1: Network scan ----
echo "--- TEST 1: Network Layer (localhost) ---"
$AISCAN scan -t localhost -l network --timeout 5 --no-color 2>&1 | tee "$RESULTS_DIR/network.txt"
echo ""

# ---- Test 2: WebApp scan ----
echo "--- TEST 2: WebApp Layer (vulnerable server) ---"
$AISCAN scan -t http://localhost:8080 -l webapp --timeout 10 --no-color 2>&1 | tee "$RESULTS_DIR/webapp.txt"
echo ""

# ---- Test 3: LLM scan ----
echo "--- TEST 3: LLM Layer (mock LLM) ---"
$AISCAN scan -t http://localhost:11434 -l llm --timeout 15 --no-color 2>&1 | tee "$RESULTS_DIR/llm.txt"
echo ""

# ---- Test 4: Full scan with JSON output ----
echo "--- TEST 4: Full scan → JSON report ---"
$AISCAN scan -t http://localhost:8080 -l webapp,llm -F json -o "$RESULTS_DIR/full-report.json" --fail-on none --no-color 2>&1
echo "  Report: $RESULTS_DIR/full-report.json"
echo ""

# ---- Cleanup ----
echo "=== Cleanup ==="
kill $VULN_WEB_PID 2>/dev/null && echo "  Stopped vuln-web"
kill $MOCK_LLM_PID 2>/dev/null && echo "  Stopped mock-llm"
cd "$TESTENV"
docker compose down 2>/dev/null && echo "  Stopped Docker services"

echo ""
echo "=== Results Summary ==="
echo "Network findings: $(grep -c 'NET-' "$RESULTS_DIR/network.txt" 2>/dev/null || echo 0)"
echo "WebApp findings:  $(grep -c 'WEB-' "$RESULTS_DIR/webapp.txt" 2>/dev/null || echo 0)"
echo "LLM findings:     $(grep -c 'LLM' "$RESULTS_DIR/llm.txt" 2>/dev/null || echo 0)"
echo ""
echo "Full results in: $RESULTS_DIR/"
