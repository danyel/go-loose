package behaviour

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// openAPIDocument is a minimal but real OpenAPI 3.1 description, used both
// pasted into the console and served over HTTP for the scan-a-URL flow.
const openAPIDocument = `{
  "openapi": "3.1.0",
  "info": {"title": "Guess API", "version": "1.0.0"},
  "paths": {
    "/health": {
      "get": {
        "operationId": "health",
        "summary": "Liveness probe",
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/guesses": {
      "get": {
        "operationId": "listGuesses",
        "summary": "List guesses",
        "responses": {"200": {"description": "ok"}}
      },
      "post": {
        "operationId": "createGuess",
        "summary": "Create a guess",
        "responses": {"201": {"description": "created"}}
      }
    }
  }
}`

// contractPhases imports a service contract from a pasted document and from a
// scanned URL, which is the path an operator takes when registering an
// application.
func contractPhases(t *testing.T, j *journey) {
	t.Helper()
	host := j.adminHost()

	phase(t, "a pasted contract is imported with its endpoints", func(t *testing.T) {
		type saved struct {
			ID            string `json:"id"`
			Version       string `json:"version"`
			EndpointCount int    `json:"endpoint_count"`
		}
		response := j.admin.json(http.MethodPost, host, "/api/v1/contracts", map[string]any{
			"application_id": j.applicationID, "source_type": "document", "document": openAPIDocument,
		})
		contract := decode[saved](t, response, http.StatusCreated)
		if contract.Version != "3.1.0" {
			t.Errorf("version = %q", contract.Version)
		}
		if contract.EndpointCount != 3 {
			t.Errorf("endpoint_count = %d, want 3", contract.EndpointCount)
		}
		j.contractID = contract.ID

		// The endpoints themselves must be queryable, since the console lists them.
		var scanned int
		if err := j.h.db.QueryRowContext(t.Context(),
			`SELECT count(*) FROM contract_endpoints WHERE contract_id = $1`, contract.ID).Scan(&scanned); err != nil {
			t.Fatalf("count contract endpoints: %v", err)
		}
		if scanned != 3 {
			t.Errorf("stored endpoints = %d, want 3", scanned)
		}
	})

	phase(t, "a malformed contract is refused with a readable error", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host, "/api/v1/contracts", map[string]any{
			"application_id": j.applicationID, "source_type": "document", "document": `{"openapi":`,
		})
		body := statusOnly(t, response, http.StatusUnprocessableEntity)
		if body == "" {
			t.Error("no explanation returned")
		}
	})

	phase(t, "an empty contract is refused", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host, "/api/v1/contracts", map[string]any{
			"application_id": j.applicationID, "source_type": "document", "document": "",
		})
		statusOnly(t, response, http.StatusBadRequest)
	})

	phase(t, "a contract is scanned from a URL", func(t *testing.T) {
		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(openAPIDocument))
		}))
		defer source.Close()

		type scanned struct {
			ID        string `json:"id"`
			SourceURL string `json:"source_url"`
		}
		response := j.admin.json(http.MethodPost, host, "/api/v1/contracts", map[string]any{
			"application_id": j.applicationID, "source_type": "url", "source_url": source.URL + "/openapi.json",
		})
		result := decode[scanned](t, response, http.StatusCreated)
		if result.SourceURL == "" {
			t.Error("the source URL was not recorded")
		}
	})

	phase(t, "an unreachable contract URL reports a gateway error", func(t *testing.T) {
		response := j.admin.json(http.MethodPost, host, "/api/v1/contracts", map[string]any{
			"application_id": j.applicationID, "source_type": "url",
			"source_url": "http://127.0.0.1:1/openapi.json",
		})
		statusOnly(t, response, http.StatusBadGateway)
	})

	phase(t, "the dashboard reports the stored contracts", func(t *testing.T) {
		type listing struct {
			Contracts []map[string]any `json:"contracts"`
		}
		result := decode[listing](t, j.admin.get(host, "/api/v1/dashboard", nil), http.StatusOK)
		if len(result.Contracts) < 2 {
			t.Errorf("contracts = %d, want the pasted and scanned documents", len(result.Contracts))
		}
	})
}
