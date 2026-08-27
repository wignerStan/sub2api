package service

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodexFingerprintSessionPreservesRootChildThreadTopology(t *testing.T) {
	account := newTestOAuthAccount(77, map[string]any{
		codexFingerprintModeExtraKey: "session",
	})

	rootRaw := "root-thread-raw"
	childRaw := "child-thread-raw"
	sharedSession := "shared-session"

	rootHeaders := http.Header{}
	rootHeaders.Set("session-id", sharedSession)
	rootHeaders.Set("thread-id", rootRaw)
	rootHeaders.Set("x-codex-turn-metadata", `{"session_id":"shared-session","thread_id":"root-thread-raw"}`)

	childHeaders := http.Header{}
	childHeaders.Set("session-id", sharedSession)
	childHeaders.Set("thread-id", childRaw)
	childHeaders.Set("x-codex-parent-thread-id", rootRaw)
	childHeaders.Set("x-codex-turn-metadata", `{"session_id":"shared-session","thread_id":"child-thread-raw","parent_thread_id":"root-thread-raw","forked_from_thread_id":"root-thread-raw"}`)

	rootIDs := resolveCodexFingerprintIDsFromRequest(account, rootHeaders)
	childIDs := resolveCodexFingerprintIDsFromRequest(account, childHeaders)
	require.NotNil(t, rootIDs)
	require.NotNil(t, childIDs)

	assert.Equal(t, rootIDs.sessionID, childIDs.sessionID, "root and child remain in one converged session")
	assert.NotEqual(t, rootIDs.threadID, childIDs.threadID, "distinct Codex threads must not collapse")
	assert.Equal(t, rootIDs.threadID, childIDs.parentThreadID, "child parent edge must target the mapped root")
	assert.Equal(t, rootIDs.threadID, childIDs.forkedFromThreadID, "fork edge must target the same mapped root")

	forwardedHeaders := childHeaders.Clone()
	applyCodexFingerprintHeaders(forwardedHeaders, childIDs)
	assert.Equal(t, childIDs.threadID, forwardedHeaders.Get("thread-id"))
	assert.Equal(t, childIDs.threadID, forwardedHeaders.Get("x-client-request-id"))
	assert.Equal(t, rootIDs.threadID, forwardedHeaders.Get("x-codex-parent-thread-id"))

	var headerMetadata map[string]any
	require.NoError(t, json.Unmarshal([]byte(forwardedHeaders.Get("x-codex-turn-metadata")), &headerMetadata))
	assert.Equal(t, childIDs.threadID, headerMetadata["thread_id"])
	assert.Equal(t, rootIDs.threadID, headerMetadata["parent_thread_id"])
	assert.Equal(t, rootIDs.threadID, headerMetadata["forked_from_thread_id"])

	body := map[string]any{
		"client_metadata": map[string]any{
			"session_id":               "account-scoped-session",
			"thread_id":                "account-scoped-child",
			"x-codex-parent-thread-id": "account-scoped-root",
			"x-codex-window-id":        "account-scoped-child:0",
			"x-codex-turn-metadata":    `{"session_id":"account-scoped-session","thread_id":"account-scoped-child","parent_thread_id":"account-scoped-root","forked_from_thread_id":"account-scoped-root"}`,
		},
	}
	require.True(t, applyCodexFingerprintClientMetadata(body, childIDs))

	clientMetadata := body["client_metadata"].(map[string]any)
	assert.Equal(t, childIDs.threadID, clientMetadata["thread_id"])
	assert.Equal(t, rootIDs.threadID, clientMetadata["x-codex-parent-thread-id"])

	var bodyMetadata map[string]any
	require.NoError(t, json.Unmarshal([]byte(clientMetadata["x-codex-turn-metadata"].(string)), &bodyMetadata))
	assert.Equal(t, childIDs.threadID, bodyMetadata["thread_id"])
	assert.Equal(t, rootIDs.threadID, bodyMetadata["parent_thread_id"])
	assert.Equal(t, rootIDs.threadID, bodyMetadata["forked_from_thread_id"])
}
