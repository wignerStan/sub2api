package responseheaders

import (
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

func TestFilterHeadersDisabledUsesDefaultAllowlist(t *testing.T) {
	src := http.Header{}
	src.Add("Content-Type", "application/json")
	src.Add("X-Request-Id", "req-123")
	src.Add("X-Test", "ok")
	src.Add("Connection", "keep-alive")
	src.Add("Content-Length", "123")

	cfg := config.ResponseHeaderConfig{
		Enabled:     false,
		ForceRemove: []string{"x-request-id"},
	}

	filtered := FilterHeaders(src, CompileHeaderFilter(cfg))
	if filtered.Get("Content-Type") != "application/json" {
		t.Fatalf("expected Content-Type passthrough, got %q", filtered.Get("Content-Type"))
	}
	if filtered.Get("X-Request-Id") != "req-123" {
		t.Fatalf("expected X-Request-Id allowed, got %q", filtered.Get("X-Request-Id"))
	}
	if filtered.Get("X-Test") != "" {
		t.Fatalf("expected X-Test removed, got %q", filtered.Get("X-Test"))
	}
	if filtered.Get("Connection") != "" {
		t.Fatalf("expected Connection to be removed, got %q", filtered.Get("Connection"))
	}
	if filtered.Get("Content-Length") != "" {
		t.Fatalf("expected Content-Length to be removed, got %q", filtered.Get("Content-Length"))
	}
}

func TestFilterHeadersAllowsReasoningIncludedByDefault(t *testing.T) {
	src := http.Header{}
	src.Set("X-Reasoning-Included", "1")

	filtered := FilterHeaders(src, CompileHeaderFilter(config.ResponseHeaderConfig{}))
	if got := filtered.Get("X-Reasoning-Included"); got != "1" {
		t.Fatalf("expected X-Reasoning-Included passthrough, got %q", got)
	}
}

func TestFilterHeadersForceRemoveOverridesReasoningIncluded(t *testing.T) {
	src := http.Header{}
	src.Set("X-Reasoning-Included", "1")

	filtered := FilterHeaders(src, CompileHeaderFilter(config.ResponseHeaderConfig{
		Enabled:     true,
		ForceRemove: []string{"x-reasoning-included"},
	}))
	if got := filtered.Get("X-Reasoning-Included"); got != "" {
		t.Fatalf("expected X-Reasoning-Included removal, got %q", got)
	}
}

func TestFilterHeadersEnabledUsesAllowlist(t *testing.T) {
	src := http.Header{}
	src.Add("Content-Type", "application/json")
	src.Add("X-Extra", "ok")
	src.Add("X-Remove", "nope")
	src.Add("X-Blocked", "nope")

	cfg := config.ResponseHeaderConfig{
		Enabled:           true,
		AdditionalAllowed: []string{"x-extra"},
		ForceRemove:       []string{"x-remove"},
	}

	filtered := FilterHeaders(src, CompileHeaderFilter(cfg))
	if filtered.Get("Content-Type") != "application/json" {
		t.Fatalf("expected Content-Type allowed, got %q", filtered.Get("Content-Type"))
	}
	if filtered.Get("X-Extra") != "ok" {
		t.Fatalf("expected X-Extra allowed, got %q", filtered.Get("X-Extra"))
	}
	if filtered.Get("X-Remove") != "" {
		t.Fatalf("expected X-Remove removed, got %q", filtered.Get("X-Remove"))
	}
	if filtered.Get("X-Blocked") != "" {
		t.Fatalf("expected X-Blocked removed, got %q", filtered.Get("X-Blocked"))
	}
}

func TestIsCodexQuotaHeader(t *testing.T) {
	quotaHeaders := []string{
		"X-Codex-Primary-Used-Percent",
		"x-codex-primary-window-minutes",
		"X-Codex-Primary-Reset-At",
		"x-codex-primary-reset-after-seconds",
		"X-Codex-Secondary-Used-Percent",
		"x-codex-secondary-window-minutes",
		"X-Codex-Secondary-Reset-At",
		"x-codex-secondary-reset-after-seconds",
		"X-Codex-Primary-Over-Secondary-Limit-Percent",
		"X-Codex-Active-Limit",
		"X-Codex-Limit-Name",
		"X-Codex-Bengalfox-Primary-Used-Percent",
		"X-Bengalfox-Primary-Used-Percent",
		"X-Codex-Credits-Has-Credits",
		"X-Codex-Credits-Unlimited",
		"X-Codex-Credits-Balance",
		"X-Codex-Promo-Message",
		"X-Codex-Rate-Limit-Reached-Type",
	}
	for _, header := range quotaHeaders {
		t.Run(header, func(t *testing.T) {
			if !IsCodexQuotaHeader(header) {
				t.Fatalf("expected %q to be classified as Codex quota metadata", header)
			}
		})
	}

	nonQuotaHeaders := []string{
		"X-Codex-Turn-State",
		"X-Codex-Window-Id",
		"X-Reasoning-Included",
		"X-Request-Id",
		"X-RateLimit-Remaining-Requests",
		"X-Bengalfox-Limit-Name",
		"X-Trace-Limit-Name",
		"Primary-Used-Percent",
		"X-Primary-Used-Percent",
	}
	for _, header := range nonQuotaHeaders {
		t.Run(header, func(t *testing.T) {
			if IsCodexQuotaHeader(header) {
				t.Fatalf("expected %q to remain available as non-quota metadata", header)
			}
		})
	}
}

func TestFilterHeadersCodexQuotaCannotBeAllowlisted(t *testing.T) {
	src := http.Header{}
	src.Set("X-Codex-Primary-Used-Percent", "81")
	src.Set("X-Bengalfox-Primary-Used-Percent", "63")
	src.Set("X-Codex-Credits-Balance", "12.34")
	src.Set("X-Codex-Active-Limit", "bengalfox")
	src.Set("X-Request-Id", "req-123")
	src.Set("X-Reasoning-Included", "1")

	filtered := FilterHeaders(src, CompileHeaderFilter(config.ResponseHeaderConfig{
		Enabled: true,
		AdditionalAllowed: []string{
			"x-codex-primary-used-percent",
			"x-bengalfox-primary-used-percent",
			"x-codex-credits-balance",
			"x-codex-active-limit",
		},
	}))

	for _, header := range []string{
		"X-Codex-Primary-Used-Percent",
		"X-Bengalfox-Primary-Used-Percent",
		"X-Codex-Credits-Balance",
		"X-Codex-Active-Limit",
	} {
		if got := filtered.Get(header); got != "" {
			t.Fatalf("expected %s to be removed, got %q", header, got)
		}
	}
	if got := filtered.Get("X-Request-Id"); got != "req-123" {
		t.Fatalf("expected X-Request-Id passthrough, got %q", got)
	}
	if got := filtered.Get("X-Reasoning-Included"); got != "1" {
		t.Fatalf("expected X-Reasoning-Included passthrough, got %q", got)
	}
}

func TestFilterHeadersAllowsUnrelatedLimitName(t *testing.T) {
	src := http.Header{}
	src.Set("X-Bengalfox-Limit-Name", "Bengalfox")

	filtered := FilterHeaders(src, CompileHeaderFilter(config.ResponseHeaderConfig{
		Enabled:           true,
		AdditionalAllowed: []string{"x-bengalfox-limit-name"},
	}))

	if got := filtered.Get("X-Bengalfox-Limit-Name"); got != "Bengalfox" {
		t.Fatalf("expected unrelated limit-name passthrough, got %q", got)
	}
}

func TestWriteFilteredHeadersRemovesStaleCodexQuota(t *testing.T) {
	dst := http.Header{
		"X-Codex-Primary-Used-Percent": []string{"99"},
		"X-Codex-Turn-State":           []string{"turn-state"},
	}
	src := http.Header{
		"X-Request-Id": []string{"req-456"},
	}

	WriteFilteredHeaders(dst, src, nil)

	if got := dst.Get("X-Codex-Primary-Used-Percent"); got != "" {
		t.Fatalf("expected stale Codex quota header removal, got %q", got)
	}
	if got := dst.Get("X-Codex-Turn-State"); got != "turn-state" {
		t.Fatalf("expected turn-state preservation, got %q", got)
	}
	if got := dst.Get("X-Request-Id"); got != "req-456" {
		t.Fatalf("expected filtered header write, got %q", got)
	}
}
