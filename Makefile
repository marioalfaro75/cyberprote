.PHONY: build test lint run-collector docker-up docker-down clean generate

GO ?= go
BINARY_NAME := csf-collector
BUILD_DIR := build
COLLECTOR_CONFIG := collector-config.yaml

# Build the custom OTel collector
build:
	$(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/collector/

# Run all tests
test:
	$(GO) test ./... -v -race -count=1

# Run tests with coverage
test-cover:
	$(GO) test ./... -v -race -coverprofile=coverage.out
	$(GO) tool cover -html=coverage.out -o coverage.html

# Run linter
lint:
	golangci-lint run ./...

# Run the collector with default config
run-collector: build
	./$(BUILD_DIR)/$(BINARY_NAME) --config $(COLLECTOR_CONFIG)

# Start infrastructure (PostgreSQL + AGE, Grafana)
docker-up:
	docker compose up -d

# Stop infrastructure
docker-down:
	docker compose down

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html

# Format code
fmt:
	$(GO) fmt ./...

# Vet code
vet:
	$(GO) vet ./...

# Run seed script
seed:
	$(GO) run ./scripts/seed-graph/
