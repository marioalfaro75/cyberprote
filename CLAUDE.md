# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cloud Security Fabric (CSF) — an open-source platform that unifies security findings from AWS Security Hub, GitHub GHAS, GCP SCC, and Azure Defender into a security graph. Uses OpenTelemetry Collector as the pipeline, OCSF as the normalization schema, and Apache AGE (on PostgreSQL) as the graph database.

Go module: `github.com/cloud-security-fabric/csf`

## Build & Test Commands

```bash
# Build collector and API binaries
make build                                    # builds build/csf-collector
go build -o build/csf-api ./cmd/api/          # builds API server

# Run all tests
make test                                     # go test ./... -v -race -count=1

# Run a single package's tests
go test ./internal/ocsf/... -v
go test ./receiver/awssechubreceiver/... -v

# Lint / vet / format
make lint                                     # golangci-lint
make vet                                      # go vet
make fmt                                      # go fmt

# Infrastructure
make docker-up                                # PostgreSQL+AGE + Grafana
make docker-down

# Seed sample data (requires running collector)
make seed

# Dashboard (React)
cd dashboard && npm ci && npm run dev         # dev server
cd dashboard && npm run build                 # production build
```

## Architecture

The project is a custom OpenTelemetry Collector with security-specific components:

**Pipeline flow:** Receivers → Processors → Exporters

- **Receivers** (`receiver/`) — Poll source APIs, emit OTel log records:
  - `awssechubreceiver` — AWS Security Hub (ASFF → OCSF)
  - `githubghasreceiver` — GitHub GHAS (CodeQL SARIF, Dependabot, Secret Scanning → OCSF)
  - `gcpsccreceiver` — GCP Security Command Center (stub)
  - `azuredefenderreceiver` — Azure Defender for Cloud (stub)

- **Processors** (`processor/`) — Transform and enrich:
  - `ocsftransformprocessor` — Platform detection, OCSF validation, EPSS/KEV enrichment
  - `secgraphprocessor` — Extract graph relationships, detect toxic patterns

- **Exporter** (`exporter/agegraphexporter/`) — Batch-upsert OCSF findings into Apache AGE graph

- **OCSF types** (`internal/ocsf/`) — Go structs for OCSF classes 2001-2006 with validation

- **Graph layer** (`internal/graph/`) — AGE graph service, schema, toxic combination Cypher queries

- **API server** (`cmd/api/`, `api/`) — REST API serving findings, risk scores, policy evaluation

- **Policy engine** (`policy/`) — OPA-based Rego policy evaluation with embedded policies

- **Scoring** (`scoring/`) — Composite risk score (0-100) with configurable weights

- **Dashboard** (`dashboard/`) — React 18 + TypeScript + Vite + Tailwind CSS

## Key Conventions

- Each OTel component follows the standard factory pattern: `config.go`, `factory.go`, `receiver.go`/`processor.go`/`exporter.go`
- OTel Collector v0.120.0 API: use `consumer.Capabilities` (not `component.Capabilities`), `ConsumeLogs` (not `ProcessLogs`), component-specific `MakeFactoryMap` functions
- OCSF class UIDs: SecurityFinding=2001, VulnerabilityFinding=2002, ComplianceFinding=2003, DetectionFinding=2004, DataSecurityFinding=2006
- Mapper tests use real JSON fixtures in `testdata/` directories
- Graph queries use Apache AGE Cypher syntax (not Neo4j)
- OPA policies use `package csf.<policy_name>` namespace with `result := {"decision": "...", "reason": reason}` pattern
- The collector entry point (`cmd/collector/main.go`) wires all components; `Factories` must be a function, not a value
