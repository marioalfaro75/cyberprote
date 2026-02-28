#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

SEED=true
PIDFILE="$ROOT_DIR/.csf.pids"

usage() {
  echo "Usage: $0 [--no-seed] [--stop] [--help]"
  echo ""
  echo "  --no-seed   Skip seeding sample data"
  echo "  --stop      Stop all running CSF services"
  echo "  --help      Show this help"
}

stop_services() {
  echo "Stopping CSF services..."

  if [ -f "$PIDFILE" ]; then
    while read -r pid name; do
      if kill -0 "$pid" 2>/dev/null; then
        echo "  Stopping $name (PID $pid)"
        kill "$pid" 2>/dev/null || true
      fi
    done < "$PIDFILE"
    rm -f "$PIDFILE"
  fi

  docker compose down 2>/dev/null || true
  echo "All services stopped."
}

wait_for_healthy() {
  local url="$1"
  local label="$2"
  local max_attempts="${3:-30}"
  local attempt=0

  while [ $attempt -lt $max_attempts ]; do
    if curl -sf "$url" >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  echo "ERROR: $label did not become healthy after ${max_attempts}s"
  return 1
}

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --no-seed) SEED=false ;;
    --stop)    stop_services; exit 0 ;;
    --help)    usage; exit 0 ;;
    *)         echo "Unknown option: $arg"; usage; exit 1 ;;
  esac
done

# Stop any previously running services
if [ -f "$PIDFILE" ]; then
  stop_services
fi

echo "=== Starting Cloud Security Fabric ==="
echo ""

# 1. Database
echo "[1/4] Starting PostgreSQL + Apache AGE..."
docker compose up -d
echo "  Waiting for database to be healthy..."
wait_for_healthy "" "PostgreSQL" 0 || true  # health check is via docker, not HTTP
# Wait for docker health check
attempts=0
while [ $attempts -lt 30 ]; do
  status=$(docker inspect --format='{{.State.Health.Status}}' csf-postgres 2>/dev/null || echo "starting")
  if [ "$status" = "healthy" ]; then
    echo "  Database is ready."
    break
  fi
  attempts=$((attempts + 1))
  sleep 1
done
if [ "$status" != "healthy" ]; then
  echo "  WARNING: Database health check did not pass after 30s. Continuing anyway..."
fi
echo ""

# 2. Collector
echo "[2/4] Building and starting collector..."
make build
./build/csf-collector --config collector-config.yaml > /tmp/csf-collector.log 2>&1 &
COLLECTOR_PID=$!
echo "$COLLECTOR_PID collector" > "$PIDFILE"
echo "  Collector started (PID $COLLECTOR_PID, log: /tmp/csf-collector.log)"
echo "  Waiting for OTLP endpoint..."
wait_for_healthy "http://localhost:13133" "Collector"
echo "  Collector is ready."
echo ""

# 3. API server
echo "[3/4] Building and starting API server..."
go build -o build/csf-api ./cmd/api/
./build/csf-api > /tmp/csf-api.log 2>&1 &
API_PID=$!
echo "$API_PID api" >> "$PIDFILE"
echo "  API started (PID $API_PID, log: /tmp/csf-api.log)"
echo "  Waiting for API endpoint..."
wait_for_healthy "http://localhost:8080/api/v1/health" "API"
echo "  API is ready."
echo ""

# 4. Seed data
if [ "$SEED" = true ]; then
  echo "[4/4] Seeding sample data..."
  go run ./scripts/seed-graph/
  echo "  Sample data seeded."
else
  echo "[4/4] Skipping seed (--no-seed)."
fi

echo ""
echo "=== CSF is running ==="
echo ""
echo "  Collector OTLP:  http://localhost:4318"
echo "  Collector zPages: http://localhost:55679"
echo "  API server:       http://localhost:8080"
echo "  API health:       http://localhost:8080/api/v1/health"
echo ""
echo "  Start the dashboard separately:"
echo "    cd dashboard && npm ci && npm run dev"
echo ""
echo "  To stop all services:"
echo "    $0 --stop"
