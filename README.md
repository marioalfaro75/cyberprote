# Cloud Security Fabric (CSF)

Unify security findings from AWS, GitHub, GCP, and Azure into a single security graph.

CSF is an open-source platform built on top of a custom [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/). It ingests findings from multiple cloud security sources, normalizes them to [OCSF](https://ocsf.io/), and stores them in an [Apache AGE](https://age.apache.org/) graph database for cross-cloud correlation and toxic-combination detection.

## Features

- **Multi-cloud ingestion** — Receivers for AWS Security Hub, GitHub GHAS (CodeQL, Dependabot, Secret Scanning), GCP Security Command Center, and Azure Defender
- **OCSF normalization** — All findings mapped to OCSF classes 2001-2006 (Security, Vulnerability, Compliance, Detection, Data Security)
- **Security graph** — Apache AGE on PostgreSQL stores findings, resources, and relationships as a property graph
- **Toxic-combination detection** — Cypher queries identify dangerous cross-finding patterns
- **Policy engine** — OPA/Rego policies for automated evaluation of security posture
- **Composite risk scoring** — Weighted 0-100 score combining CVSS, EPSS, KEV, blast radius, and policy results
- **REST API** — Query findings, risk scores, and policy evaluations
- **Dashboard** — React + TypeScript + Vite + Tailwind CSS UI

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                      OTel Collector Pipeline                        │
│                                                                      │
│  ┌─────────────┐   ┌──────────────────────┐   ┌──────────────────┐  │
│  │  Receivers   │──▶│     Processors       │──▶│    Exporter      │  │
│  │             │   │                      │   │                  │  │
│  │ AWS SecHub  │   │ ocsftransform        │   │ agegraphexporter │  │
│  │ GitHub GHAS │   │  · OCSF validation   │   │  · Batch upsert  │  │
│  │ GCP SCC     │   │  · EPSS/KEV enrich   │   │  · Apache AGE    │  │
│  │ Azure Def.  │   │                      │   │                  │  │
│  │             │   │ secgraph             │   │                  │  │
│  │             │   │  · Relationship      │   │                  │  │
│  │             │   │    extraction        │   │                  │  │
│  │             │   │  · Toxic patterns    │   │                  │  │
│  └─────────────┘   └──────────────────────┘   └────────┬─────────┘  │
└──────────────────────────────────────────────────────────┼───────────┘
                                                          │
                                                          ▼
                                              ┌──────────────────────┐
                                              │  PostgreSQL + AGE    │
                                              │  (Security Graph)    │
                                              └──────────┬───────────┘
                                                         │
                                              ┌──────────▼───────────┐
                                              │     REST API         │
                                              │  Findings · Scores   │
                                              │  Policy evaluation   │
                                              └──────────┬───────────┘
                                                         │
                                              ┌──────────▼───────────┐
                                              │     Dashboard        │
                                              │  React + Tailwind    │
                                              └──────────────────────┘
```

## Quick Start

### Prerequisites

- Go 1.25+
- Docker & Docker Compose
- Node.js 18+ (for dashboard)

### 1. Start infrastructure

```bash
docker compose up -d          # PostgreSQL + Apache AGE
```

### 2. Build and run the collector

```bash
make build                    # builds build/csf-collector
./build/csf-collector --config collector-config.yaml
```

### 3. Build and run the API server

```bash
go build -o build/csf-api ./cmd/api/
./build/csf-api
```

### 4. Start the dashboard

```bash
cd dashboard && npm ci && npm run dev
```

### 5. (Optional) Seed sample data

```bash
make seed
```

## Project Structure

```
cmd/
  collector/          Custom OTel Collector entry point
  api/                REST API server
receiver/
  awssechubreceiver/        AWS Security Hub → OCSF
  githubghasreceiver/       GitHub GHAS → OCSF
  gcpsccreceiver/           GCP Security Command Center (stub)
  azuredefenderreceiver/    Azure Defender (stub)
processor/
  ocsftransformprocessor/   OCSF validation, EPSS/KEV enrichment
  secgraphprocessor/        Graph relationship extraction, toxic patterns
exporter/
  agegraphexporter/         Batch upsert to Apache AGE
internal/
  ocsf/               OCSF Go types (classes 2001-2006) with validation
  graph/               AGE graph service, schema, Cypher queries
api/                   API route handlers and middleware
policy/                OPA/Rego policies
scoring/               Composite risk scoring engine
dashboard/             React + TypeScript + Vite + Tailwind CSS
helm/csf/              Helm chart for Kubernetes deployment
scripts/               Seed scripts and utilities
```

## Development

```bash
make build          # Build collector binary
make test           # Run all tests (race detector enabled)
make lint           # golangci-lint
make vet            # go vet
make fmt            # go fmt
make docker-up      # Start PostgreSQL + AGE
make docker-down    # Stop infrastructure
make seed           # Seed sample graph data
```

Run a single package's tests:

```bash
go test ./internal/ocsf/... -v
go test ./receiver/awssechubreceiver/... -v
```

## Deployment

A Helm chart is provided in `helm/csf/` for Kubernetes deployments:

```bash
helm install csf ./helm/csf -f helm/csf/values.yaml
```

## License

TBD
