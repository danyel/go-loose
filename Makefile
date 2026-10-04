SHELL := /bin/sh

GO_LOOSE_ADDR ?= :8081
GO_LOOSE_PORT ?= 8081
GO_LOOSE_BASE_URL ?= http://localhost:$(GO_LOOSE_PORT)
GO_LOOSE_DATABASE_URL ?= postgres://goloose:goloose@localhost:5433/goloose?sslmode=disable
GO_LOOSE_SESSION_SECRET ?= local-development-secret-change-me-now
GO_LOOSE_DEV_LOGIN ?= true
GO_LOOSE_DEV_USER ?= admin@local.test
GO_LOOSE_BOOTSTRAP_TENANT ?= nmbs
GO_LOOSE_BOOTSTRAP_APP ?= guess
GO_LOOSE_ALLOW_PRIVATE_CONTRACT_URLS ?= true

export

.PHONY: build test integration-test run compose-up compose-down fmt vet

build:
	go build ./...

test:
	go test -race ./...

# Integration tests truncate every table in the target database, so point them at
# a scratch database rather than one holding real data.
integration-test:
	@test -n "$(GO_LOOSE_TEST_DATABASE_URL)" || { echo "set GO_LOOSE_TEST_DATABASE_URL to a scratch database"; exit 1; }
	go test -race ./internal/store/ -count=1

run:
	go run ./cmd/go-loose

# The variables above are exported for `make run`, but compose reads
# GO_LOOSE_BASE_URL too and would inherit the local http://localhost:8081 value,
# which then overrides the https:// defaults in docker-compose.yaml. Clearing it
# for the compose targets lets compose apply its own defaults.
compose-up:
	GO_LOOSE_BASE_URL= docker compose up --build

compose-down:
	docker compose down

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

vet:
	go vet ./...
