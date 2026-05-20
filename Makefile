SHELL := /bin/bash
BIN   := bin
PKGS  := ./...

.PHONY: help build test lint fmt tidy dev-up dev-down demo bench formal clean

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

build: ## Build agentd, agentfw, agentctl
	@mkdir -p $(BIN)
	go build -o $(BIN)/agentd   ./cmd/agentd
	go build -o $(BIN)/agentfw  ./cmd/agentfw
	go build -o $(BIN)/agentctl ./cmd/agentctl

test: ## Unit + property tests
	go test -race -coverprofile=coverage.out $(PKGS)

lint: ## golangci-lint
	golangci-lint run

fmt: ## gofmt + goimports
	gofmt -l -w . && go run golang.org/x/tools/cmd/goimports@latest -w .

tidy: ## go mod tidy across modules
	go mod tidy && (cd sdk/go && go mod tidy) && (cd abench && go mod tidy)

dev-up: ## Start local stack (WSO2, step-ca, agentd, 2x agentfw, mock-sap, otel)
	docker compose -f deploy/docker/docker-compose.yaml up -d --wait
	./deploy/docker/wso2/seed.sh

dev-down: ## Tear down local stack
	docker compose -f deploy/docker/docker-compose.yaml down -v

demo: ## Run the 14 acceptance scenarios against the local stack
	go test -tags=e2e -count=1 -v ./test/e2e/...

bench: ## Run the benchmark harness (see abench/README.md)
	cd abench && go run ./harness

formal: ## Model-check the budget lease protocol
	cd formal && ./check.sh

clean:
	rm -rf $(BIN) coverage.out
