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
- **Threat intelligence** — MITRE ATT&CK matrix mapping, Shodan exposure lookup, NVD/CVE enrichment
- **REST API** — Query findings, risk scores, policy evaluations, and threat intel
- **Dashboard** — React + TypeScript + Vite + Tailwind CSS UI with light/dark/system theme

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
                                              │  Policy · Threat Intel│
                                              └──────────┬───────────┘
                                                         │
                                              ┌──────────▼───────────┐
                                              │     Dashboard        │
                                              │  React + Tailwind    │
                                              └──────────────────────┘
```

## Quick Start

You can start the full stack manually step-by-step, or use the `scripts/start.sh` helper to bring everything up at once.

### Prerequisites

- Go 1.25+
- Docker & Docker Compose
- Node.js 18+ (for dashboard)

### Option A: One command

```bash
./scripts/start.sh            # starts all services, seeds sample data
./scripts/start.sh --no-seed  # skip seeding
./scripts/start.sh --stop     # tear everything down
```

### Option B: Step by step

#### 1. Start the database

```bash
docker compose up -d
```

PostgreSQL with Apache AGE starts on port 5432. Graph schema migrations run automatically on first boot. Wait a few seconds for the health check to pass:

```bash
docker compose ps              # STATE should be "running (healthy)"
```

#### 2. Build and run the collector

```bash
make build                     # builds build/csf-collector
./build/csf-collector --config collector-config.yaml &
```

The collector listens on:
- **4317** — OTLP gRPC
- **4318** — OTLP HTTP (used by the seed script)
- **8888** — Prometheus metrics
- **55679** — zPages debug UI

Without cloud credentials configured, no live data flows in — but you can seed sample data in step 5.

#### 3. Build and run the API server

```bash
go build -o build/csf-api ./cmd/api/
./build/csf-api &
```

The API runs on `http://localhost:8080`. Verify with:

```bash
curl http://localhost:8080/api/v1/health
```

#### 4. Start the dashboard

```bash
cd dashboard && npm ci && npm run dev
```

The dashboard runs on `http://localhost:3001`.

#### 5. Seed sample data

```bash
make seed
```

This sends 5 sample OCSF findings to the collector via OTLP HTTP — an AWS GuardDuty detection, an Inspector vulnerability, a Security Hub compliance finding, a GitHub CodeQL vulnerability, and a secret-scanning alert. Data flows through the pipeline into the graph and is immediately visible in the API and dashboard.

Verify data landed:

```bash
curl http://localhost:8080/api/v1/findings
curl http://localhost:8080/api/v1/graph/stats
```

#### 6. Stop everything

```bash
kill %1 %2                    # stop collector and API (background jobs)
docker compose down           # stop PostgreSQL
```

### Connecting cloud sources

To ingest live findings, uncomment and configure receivers in `collector-config.yaml`:

| Source | Credentials | How to provide |
|--------|-------------|----------------|
| **AWS Security Hub** | AWS access key or IAM role | Standard AWS SDK chain: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars, `~/.aws/credentials`, or EC2 instance role |
| **GitHub GHAS** | Personal access token or GitHub App | `export GITHUB_TOKEN=ghp_...` then reference `${GITHUB_TOKEN}` in config |
| **GCP SCC** | GCP service account key | _Receiver not yet implemented_ |
| **Azure Defender** | Azure AD app credentials | _Receiver not yet implemented_ |

Example — enable GitHub GHAS:

```yaml
# In collector-config.yaml, uncomment and edit:
githubghas:
  owner: your-org
  repos: [repo1, repo2]
  token: ${GITHUB_TOKEN}
  poll_interval: 5m
  enable_code_scanning: true
  enable_dependabot: true
  enable_secret_scanning: true
```

Then add `githubghas` to the pipeline's receivers list:

```yaml
service:
  pipelines:
    logs/security:
      receivers: [otlp, githubghas]
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
  threatintel/         MITRE ATT&CK, Shodan, NVD integration
  compliance/          Compliance framework catalog (NIST CSF, CIS)
  settings/            Persistent settings store
api/                   API route handlers and middleware
policy/                OPA/Rego policies
scoring/               Composite risk scoring engine
dashboard/             React + TypeScript + Vite + Tailwind CSS
  src/context/         Theme context (dark mode)
  src/components/      Layout, settings forms, shared components
  src/pages/           Page views (Risk, Compliance, Threat Intel, etc.)
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
