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
GO_LOOSE_DEV_PORT ?= 8080

export

.PHONY: build test integration-db integration-test behaviour-test run compose-up compose-down compose-dev-up compose-dev-down compose-dev-logs fmt vet

build:
	go build ./...

# The database-backed suites drop every table they touch, so `test` runs without
# them. Each suite skips itself when its variable is empty, which keeps a
# developer without PostgreSQL from being blocked; `integration-test` sets them.
test:
	GO_LOOSE_TEST_DATABASE_URL= GO_LOOSE_TEST_SERVER_DATABASE_URL= go test -race ./...

# Integration tests drop every table they touch, so they only run against scratch
# databases. Both test helpers refuse any database whose name lacks "test", and
# `make integration-db` creates the two they expect. Override the check with
# GO_LOOSE_TEST_DATABASE_DESTRUCTIVE=1 only when you mean it.
#
# The store-backed tests in internal/server need a database of their own: Go runs
# package tests in parallel and both packages drop every table, so sharing one
# database makes them fight over the schema.
GO_LOOSE_TEST_DATABASE_URL ?= postgres://goloose:goloose@localhost:5433/goloose_test?sslmode=disable
GO_LOOSE_TEST_SERVER_DATABASE_URL ?= postgres://goloose:goloose@localhost:5433/goloose_server_test?sslmode=disable

# The behaviour suite drives the whole application over HTTP and needs the Google
# client credentials for the installer. It reads ../google_secrets.json, or the
# variables below, and skips when neither is present.
GO_LOOSE_BEHAVIOUR_DATABASE_URL ?= postgres://goloose:goloose@localhost:5433/goloose_behaviour_test?sslmode=disable

# createdb is not idempotent, so ignore a database that is already there.
integration-db:
	-docker compose exec -T postgres createdb -U goloose goloose_test
	-docker compose exec -T postgres createdb -U goloose goloose_server_test
	-docker compose exec -T postgres createdb -U goloose goloose_behaviour_test

integration-test:
	@test -n "$(GO_LOOSE_TEST_DATABASE_URL)" || { echo "set GO_LOOSE_TEST_DATABASE_URL to a scratch database"; exit 1; }
	go test -race ./internal/store/ ./internal/server/ -count=1

# Installs the application into an empty database, walks every flow, restarts the
# process, and checks that everything is still there. Leaves the database empty
# again so the next run starts from nothing.
behaviour-test:
	GO_LOOSE_BEHAVIOUR=1 go test ./internal/behaviour/ -count=1 -v
	-docker compose exec -T postgres psql -q -U goloose -d goloose_behaviour_test \
		-c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;' >/dev/null

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

# Air rebuilds into ./dist on every change.
compose-dev-up:
	mkdir -p dist
	docker compose -f docker-compose.dev.yaml up --build

compose-dev-down:
	docker compose -f docker-compose.dev.yaml down --remove-orphans
	# Air writes dist/go-loose as root inside the container, so the host user
	# cannot delete it directly. Empty the directory through a container instead.
	-docker run --rm -v "$(CURDIR)/dist:/dist" alpine sh -c 'rm -rf /dist/*' 2>/dev/null || true

compose-dev-logs:
	docker compose -f docker-compose.dev.yaml logs -f go-loose

fmt:
	# Prune directories that are not source and may be unreadable: vendored
	# code, build output, the PostgreSQL volume, and anything hidden or
	# underscore prefixed, which is how Go itself skips package trees.
	gofmt -w $$(find . -mindepth 1 -type d \( -name vendor -o -name dist -o -name '.*' -o -name '_*' \) -prune -o -name '*.go' -print)

vet:
	go vet ./...
