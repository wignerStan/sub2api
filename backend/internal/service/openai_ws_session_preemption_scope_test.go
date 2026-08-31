package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func newOpenAIWSSessionPreemptionScopeTestContext(headers map[string]string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	for key, value := range headers {
		c.Request.Header.Set(key, value)
	}
	return c
}

func TestOpenAIWSSessionPreemptionScopeSeparatesCodexThreads(t *testing.T) {
	const sessionHash = "shared-session-hash"
	root := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{"session-id": "shared-session", "thread-id": "root-thread"})
	child := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{"session-id": "shared-session", "thread-id": "child-thread"})

	rootScope := openAIWSSessionPreemptionScope(root, nil, sessionHash)
	childScope := openAIWSSessionPreemptionScope(child, nil, sessionHash)
	require.NotEqual(t, sessionHash, rootScope)
	require.NotEqual(t, rootScope, childScope)
	require.Equal(t, childScope, openAIWSSessionPreemptionScope(child, nil, sessionHash))

	legacy := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{"session-id": "shared-session"})
	require.Equal(t, sessionHash, openAIWSSessionPreemptionScope(legacy, nil, sessionHash))
}

func TestOpenAIWSSessionPreemptionScopeReadsThreadFromFirstMessage(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
	const sessionHash = "shared-session-hash"
	body := []byte(`{"type":"response.create","client_metadata":{"thread_id":"child-from-body","x-codex-turn-metadata":"{\"thread_id\":\"child-from-metadata\"}"}}`)
	scope := openAIWSSessionPreemptionScope(c, body, sessionHash)
	require.NotEqual(t, sessionHash, scope)
	require.Equal(t, scope, openAIWSSessionPreemptionScope(c, body, sessionHash))
}

func TestOpenAIWSSessionPreemptionScopeUsesConversationIDWhenThreadHeaderMissing(t *testing.T) {
	const sessionHash = "shared-session-hash"
	root := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{
		"session-id":      "shared-session",
		"conversation_id": "root-conversation",
	})
	child := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{
		"session-id":      "shared-session",
		"conversation_id": "child-conversation",
	})
	rootScope := openAIWSSessionPreemptionScope(root, nil, sessionHash)
	childScope := openAIWSSessionPreemptionScope(child, nil, sessionHash)
	require.NotEqual(t, sessionHash, rootScope)
	require.NotEqual(t, rootScope, childScope)
}

func TestOpenAIWSSessionPreemptionScopeBodyThreadWinsHeaderConversation(t *testing.T) {
	const sessionHash = "shared-session-hash"
	c := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{
		"session-id":      "shared-session",
		"conversation_id": "conversation-fallback",
	})
	body := []byte(`{"type":"response.create","client_metadata":{"thread_id":"explicit-body-thread"}}`)

	want := DeriveSessionHashFromSeed("sub2api:openai-ws-preempt-thread:v1:" + sessionHash + ":explicit-body-thread")
	require.Equal(t, want, openAIWSSessionPreemptionScope(c, body, sessionHash))
}

func TestOpenAIWSIngressStateHashSeparatesThreadContinuationState(t *testing.T) {
	const sessionHash = "shared-session-hash"
	root := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{
		"session-id": "shared-session",
		"thread-id":  "root-thread",
	})
	child := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{
		"session-id": "shared-session",
		"thread-id":  "child-thread",
	})
	require.NotEqual(t,
		openAIWSIngressStateHash(root, nil, sessionHash),
		openAIWSIngressStateHash(child, nil, sessionHash),
	)
	legacy := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{"session-id": "shared-session"})
	require.Equal(t, sessionHash, openAIWSIngressStateHash(legacy, nil, sessionHash))
}

func TestOpenAIWSSessionPreemptionDoesNotCrossCodexThreads(t *testing.T) {
	gin.SetMode(gin.TestMode)
	groupID := int64(77)
	newContext := func(threadID string) *gin.Context {
		c := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{
			"session-id": "shared-session",
			"thread-id":  threadID,
		})
		c.Set("api_key", &APIKey{ID: 88, GroupID: &groupID})
		return c
	}
	svc := &OpenAIGatewayService{openaiWSStateStore: NewOpenAIWSStateStore(nil)}
	account := &Account{ID: 99, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	firstCtx, firstCleanup, armed := svc.BeginOpenAIWSIngressSessionPreemption(
		context.Background(), newContext("root-thread"), account,
		[]byte(`{"type":"response.create","model":"gpt-5.1"}`),
	)
	require.True(t, armed)
	defer firstCleanup()
	secondCtx, secondCleanup, armed := svc.BeginOpenAIWSIngressSessionPreemption(
		context.Background(), newContext("child-thread"), account,
		[]byte(`{"type":"response.create","model":"gpt-5.1"}`),
	)
	require.True(t, armed)
	defer secondCleanup()
	select {
	case <-firstCtx.Done():
		t.Fatalf("root thread was preempted by independent child: %v", context.Cause(firstCtx))
	default:
	}
	select {
	case <-secondCtx.Done():
		t.Fatalf("child thread was unexpectedly canceled: %v", context.Cause(secondCtx))
	default:
	}

	// A second connection for the same thread is still a replacement and must
	// preempt the earlier owner.
	thirdCtx, thirdCleanup, armed := svc.BeginOpenAIWSIngressSessionPreemption(
		context.Background(), newContext("root-thread"), account,
		[]byte(`{"type":"response.create","model":"gpt-5.1"}`),
	)
	require.True(t, armed)
	defer thirdCleanup()
	require.ErrorIs(t, context.Cause(firstCtx), errOpenAIWSSessionPreempted)
	select {
	case <-thirdCtx.Done():
		t.Fatalf("replacement root owner was canceled: %v", context.Cause(thirdCtx))
	default:
	}
}

func TestOpenAIWSSessionPreemptionIgnoresPerRequestClientRequestID(t *testing.T) {
	root := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{
		"session-id":          "shared-session",
		"x-client-request-id": "request-a",
	})
	other := newOpenAIWSSessionPreemptionScopeTestContext(map[string]string{
		"session-id":          "shared-session",
		"x-client-request-id": "request-b",
	})
	const sessionHash = "shared-session-hash"
	require.Equal(t, sessionHash, openAIWSSessionPreemptionScope(root, nil, sessionHash))
	require.Equal(t, sessionHash, openAIWSSessionPreemptionScope(other, nil, sessionHash))
}
