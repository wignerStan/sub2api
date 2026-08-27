package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestAccountHandlerConvergeCodexFingerprintsHonorsRotateSeeds(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stub := newStubAdminService()
	handler := NewAccountHandler(stub, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	router := gin.New()
	router.POST("/admin/accounts/codex-fingerprint/converge", handler.ConvergeCodexFingerprints)

	req := httptest.NewRequest(http.MethodPost, "/admin/accounts/codex-fingerprint/converge?rotate-seeds=1", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Data service.ConvergeCodexFingerprintsResult `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.True(t, payload.Data.RotateSeeds)
	require.Equal(t, len(stub.accounts), payload.Data.Matched)
}
