//go:build e2e

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func codexBaseURL() string {
	return strings.TrimRight(getEnv("BASE_URL", "http://127.0.0.1"), "/")
}

func TestCodexHardeningHealth(t *testing.T) {
	status, body := mustGet(t, codexBaseURL()+"/health", nil)
	if status != http.StatusOK {
		t.Fatalf("GET /health: HTTP %d body=%s", status, body)
	}
	if !strings.Contains(body, `"status"`) || !strings.Contains(body, `"ok"`) {
		t.Fatalf("GET /health: unexpected body %s", body)
	}
}

func TestCodexHardeningBlocksAssociationLeakPaths(t *testing.T) {
	for _, path := range []string{
		"/v1/analytics",
		"/v1/rgstr",
		"/v1/telemetry",
		"/v1/traces",
		"/v1/get_config",
	} {
		t.Run(path, func(t *testing.T) {
			status, body := mustGet(t, codexBaseURL()+path, nil)
			if status != http.StatusNotFound {
				t.Fatalf("HTTP %d body=%s", status, body)
			}
			if !strings.Contains(body, "not_found_error") {
				t.Fatalf("expected JSON 404, got %s", body)
			}
		})
	}
}

func TestCodexHardeningRejectsUnknownResponsesSubpath(t *testing.T) {
	status, body := mustPost(t, codexBaseURL()+"/v1/responses/not-compact", `{"model":"gpt-5.6-sol"}`, nil)
	if status == http.StatusOK {
		t.Fatalf("unknown /responses subpath must not succeed: %s", body)
	}
	if status == http.StatusOK || strings.Contains(body, `"status":"completed"`) {
		t.Fatalf("unknown /responses subpath leaked a completed response: %s", body)
	}
}

func TestCodexHardeningRequiresAPIKey(t *testing.T) {
	status, body := mustGet(t, codexBaseURL()+"/v1/models", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("GET /v1/models without key: HTTP %d body=%s", status, body)
	}
	status, body = mustPost(t, codexBaseURL()+"/v1/responses", `{"model":"gpt-5.6-sol","input":"ping"}`, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("POST /v1/responses without key: HTTP %d body=%s", status, body)
	}
}

func TestCodexHardeningAuthenticatedModelsAndResponses(t *testing.T) {
	key := strings.TrimSpace(os.Getenv("SUB2API_API_KEY"))
	if key == "" {
		t.Skip("SUB2API_API_KEY unset")
	}
	headers := map[string]string{"Authorization": "Bearer " + key}

	status, body := mustGet(t, codexBaseURL()+"/v1/models", headers)
	if status != http.StatusOK {
		t.Fatalf("GET /v1/models: HTTP %d body=%s", status, redact(body))
	}
	var models map[string]any
	if err := json.Unmarshal([]byte(body), &models); err != nil {
		t.Fatalf("models json: %v", err)
	}
	data, _ := models["data"].([]any)
	if len(data) == 0 {
		t.Fatalf("models data empty")
	}

	payload := `{"model":"gpt-5.6-sol","input":"Reply with the single word pong.","store":false}`
	status, body = mustPost(t, codexBaseURL()+"/v1/responses", payload, headers)
	if status != http.StatusOK {
		t.Fatalf("POST /v1/responses: HTTP %d body=%s", status, redact(body))
	}
	if !strings.Contains(body, `"status"`) {
		t.Fatalf("responses missing status: %s", redact(body))
	}
}

func mustGet(t *testing.T, url string, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return doHTTP(t, req, headers)
}

func mustPost(t *testing.T, url, payload string, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return doHTTP(t, req, headers)
}

func doHTTP(t *testing.T, req *http.Request, headers map[string]string) (int, string) {
	t.Helper()
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(raw)
}

func redact(s string) string {
	return strings.ReplaceAll(s, os.Getenv("SUB2API_API_KEY"), "sk-[redacted]")
}
