package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCodexQuotaResponseIsolation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(CodexQuotaResponseIsolation())
	engine.GET("/", func(c *gin.Context) {
		c.Header("X-Codex-Primary-Used-Percent", "81")
		c.Header("X-Codex-Primary-Reset-At", "1738888888")
		c.Header("X-Bengalfox-Primary-Used-Percent", "63")
		c.Header("X-Codex-Credits-Balance", "12.34")
		c.Header("X-Codex-Promo-Message", "provider promo")
		c.Header("X-Codex-Rate-Limit-Reached-Type", "primary")
		c.Header("X-Codex-Turn-State", "turn-state")
		c.Header("X-Request-Id", "req-123")
		c.Header("X-RateLimit-Remaining-Requests", "7")
		c.Writer.WriteHeader(http.StatusAccepted)
		_, _ = c.Writer.WriteString("ok")
	})

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}
	for _, header := range []string{
		"X-Codex-Primary-Used-Percent",
		"X-Codex-Primary-Reset-At",
		"X-Bengalfox-Primary-Used-Percent",
		"X-Codex-Credits-Balance",
		"X-Codex-Promo-Message",
		"X-Codex-Rate-Limit-Reached-Type",
	} {
		if got := recorder.Header().Get(header); got != "" {
			t.Fatalf("expected %s to be removed, got %q", header, got)
		}
	}
	if got := recorder.Header().Get("X-Codex-Turn-State"); got != "turn-state" {
		t.Fatalf("expected turn-state preservation, got %q", got)
	}
	if got := recorder.Header().Get("X-Request-Id"); got != "req-123" {
		t.Fatalf("expected request ID preservation, got %q", got)
	}
	if got := recorder.Header().Get("X-RateLimit-Remaining-Requests"); got != "7" {
		t.Fatalf("expected generic rate-limit header preservation, got %q", got)
	}
}

func TestCodexQuotaResponseIsolationScrubsWriteHeaderNow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(CodexQuotaResponseIsolation())
	engine.GET("/", func(c *gin.Context) {
		c.Header("X-Codex-Secondary-Used-Percent", "99")
		c.Header("X-Reasoning-Included", "1")
		c.Writer.WriteHeaderNow()
	})

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := recorder.Header().Get("X-Codex-Secondary-Used-Percent"); got != "" {
		t.Fatalf("expected committed quota header removal, got %q", got)
	}
	if got := recorder.Header().Get("X-Reasoning-Included"); got != "1" {
		t.Fatalf("expected reasoning metadata preservation, got %q", got)
	}
}

func TestCodexQuotaResponseIsolationScrubsHeaderOnlyResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(CodexQuotaResponseIsolation())
	engine.GET("/", func(c *gin.Context) {
		c.Header("X-Codex-Primary-Used-Percent", "54")
		c.Header("X-Request-Id", "req-header-only")
	})

	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if got := recorder.Header().Get("X-Codex-Primary-Used-Percent"); got != "" {
		t.Fatalf("expected deferred quota removal before Gin commits headers, got %q", got)
	}
	if got := recorder.Header().Get("X-Request-Id"); got != "req-header-only" {
		t.Fatalf("expected request ID preservation, got %q", got)
	}
}
