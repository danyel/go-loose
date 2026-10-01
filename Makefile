SHELL := /bin/sh

GO_LOOSE_ADDR ?= :8081
GO_LOOSE_BASE_URL ?= http://localhost:$(GO_LOOSE_PORT)
GO_LOOSE_DATABASE_URL ?= postgres://goloose:goloose@localhost:5433/goloose?sslmode=disable
GO_LOOSE_SESSION_SECRET ?= local-development-secret-change-me-now
GO_LOOSE_DEV_LOGIN ?= true
GO_LOOSE_DEV_USER ?= admin@local.test
GO_LOOSE_BOOTSTRAP_TENANT ?= nmbs
GO_LOOSE_BOOTSTRAP_APP ?= guess
GO_LOOSE_ALLOW_PRIVATE_CONTRACT_URLS ?= true

export

.PHONY: build test run compose-up compose-down fmt vet

build:
	go build ./...

test:
	go test -race ./...

run:
	go run ./cmd/go-loose

compose-up:
	docker compose up --build

compose-down:
	docker compose down

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

vet:
	go vet ./...
