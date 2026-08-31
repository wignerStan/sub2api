package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var errOpenAIWSSessionPreempted = errors.New("openai ws session preempted by newer request")

const (
	openAIWSSessionPreemptOwnerTTL      = 2 * time.Hour
	openAIWSSessionPreemptWatchInterval = 2 * time.Second
	openAIWSSessionPreemptCachePrefix   = "wspreempt:"
)

// OpenAIWSSessionPreemptionCache is an optional GatewayCache capability. The
// production Redis cache implements all operations atomically; cache stubs do
// not need to implement it for ordinary gateway tests.
type OpenAIWSSessionPreemptionCache interface {
	ClaimOpenAIResponsesSessionWindow(ctx context.Context, groupID int64, sessionHash string, owner []byte, ttl time.Duration) ([]byte, error)
	CompareAndRefreshOpenAIResponsesSessionWindow(ctx context.Context, groupID int64, sessionHash string, expected []byte, ttl time.Duration) (bool, error)
	CompareAndDeleteOpenAIResponsesSessionWindow(ctx context.Context, groupID int64, sessionHash string, expected []byte) (bool, error)
}

func NewOpenAIWSSessionPreemptedError() error {
	return errOpenAIWSSessionPreempted
}

type openAIWSSessionPreemptKey struct {
	groupID     int64
	apiKeyID    int64
	sessionHash string
}

type openAIWSSessionPreemptContextKey struct{}

// BeginOpenAIWSIngressSessionPreemption keeps a persistent inbound WS session
// registered across upstream retry attempts. Nested forwarding calls reuse the
// registration so returning from one attempt cannot create a preemption gap.
func (s *OpenAIGatewayService) BeginOpenAIWSIngressSessionPreemption(
	ctx context.Context,
	c *gin.Context,
	account *Account,
	firstClientMessage []byte,
) (context.Context, func(), bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if armed, _ := ctx.Value(openAIWSSessionPreemptContextKey{}).(bool); armed {
		return ctx, func() {}, true
	}

	preemptSessionHash := ""
	stateSessionHash := ""
	preemptGroupID := getOpenAIGroupIDFromContext(c)
	if account != nil && account.IsOpenAIOAuthLike() {
		stateSessionHash = s.GenerateSessionHash(c, firstClientMessage)
		preemptSessionHash = openAIWSSessionPreemptionScope(c, firstClientMessage, stateSessionHash)
	}
	preemptCtx, cleanup, armed, preemptedPrevious := s.beginOpenAIWSSessionPreemptContextScoped(
		ctx,
		account,
		preemptGroupID,
		getAPIKeyIDFromContext(c),
		preemptSessionHash,
		stateSessionHash,
		false,
	)
	if !armed {
		return ctx, func() {}, false
	}
	// A thread-scoped claim must not clear the shared session's sticky state:
	// root and subagent/fork threads legitimately share that state while their
	// transports remain independent.  Preserve the historical cleanup only for
	// an unscoped (session-level) claim.
	if preemptedPrevious && preemptSessionHash == stateSessionHash {
		if stateStore := s.getOpenAIWSStateStore(); stateStore != nil {
			stateStore.DeleteSessionTurnState(preemptGroupID, stateSessionHash)
			stateStore.DeleteSessionConn(preemptGroupID, stateSessionHash)
		}
	}
	return context.WithValue(preemptCtx, openAIWSSessionPreemptContextKey{}, true), cleanup, true
}

// openAIWSSessionPreemptionScope returns the ownership key for one inbound
// WebSocket.  Codex can run a root thread and several fork/subagent threads
// under one session_id; those transports must not preempt each other.  When a
// thread signal is available, derive a separate opaque scope while retaining
// the original session hash as the sticky-state key.  Older clients that do
// not expose thread metadata retain the historical session-level behavior.
func openAIWSSessionPreemptionScope(c *gin.Context, firstClientMessage []byte, stateSessionHash string) string {
	stateSessionHash = strings.TrimSpace(stateSessionHash)
	if stateSessionHash == "" {
		return ""
	}
	threadID := openAIWSSessionPreemptionThreadID(c, firstClientMessage)
	if threadID == "" {
		return stateSessionHash
	}
	return DeriveSessionHashFromSeed("sub2api:openai-ws-preempt-thread:v1:" + stateSessionHash + ":" + threadID)
}

// openAIWSIngressStateHash mirrors the preemption scope for state that is
// specific to one live ingress transport (turn-state and session->conn
// affinity).  Account scheduling still uses the unsuffixed session hash, but
// root/fork threads must not overwrite each other's continuation state.
func openAIWSIngressStateHash(c *gin.Context, firstClientMessage []byte, sessionHash string) string {
	sessionHash = strings.TrimSpace(sessionHash)
	if sessionHash == "" {
		return ""
	}
	if scoped := openAIWSSessionPreemptionScope(c, firstClientMessage, sessionHash); scoped != "" {
		return scoped
	}
	return sessionHash
}

func openAIWSSessionPreemptionThreadID(c *gin.Context, firstClientMessage []byte) string {
	var headers http.Header
	if c != nil && c.Request != nil {
		headers = c.Request.Header
	}
	// Keep this precedence identical to Codex fingerprint resolution. A real
	// thread/window carrier must win over a conversation compatibility fallback,
	// even when the former is available only in the first response.create body.
	if value := normalizeOpenAIWSSessionPreemptionThreadID(extractClientThreadID(headers)); value != "" {
		return value
	}
	if value := normalizeOpenAIWSSessionPreemptionThreadID(extractCodexBodyExplicitThreadID(firstClientMessage)); value != "" {
		return value
	}
	if value := normalizeOpenAIWSSessionPreemptionThreadID(extractClientConversationID(headers)); value != "" {
		return value
	}
	if value := normalizeOpenAIWSSessionPreemptionThreadID(extractCodexBodyConversationID(firstClientMessage)); value != "" {
		return value
	}
	// x-client-request-id is deliberately not a fallback.  Although the
	// official Codex client currently mirrors thread-id there, compatible
	// clients commonly generate a new request UUID for every frame.  Using it
	// would make one logical thread look like a new owner on each turn and can
	// preempt the very connection that is waiting for that turn.
	return ""
}

func normalizeOpenAIWSSessionPreemptionThreadID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 {
		return ""
	}
	return value
}

func newOpenAIWSSessionPreemptKey(groupID, apiKeyID int64, sessionHash string) (openAIWSSessionPreemptKey, bool) {
	sessionHash = strings.TrimSpace(sessionHash)
	if groupID <= 0 || apiKeyID <= 0 || sessionHash == "" {
		return openAIWSSessionPreemptKey{}, false
	}
	return openAIWSSessionPreemptKey{groupID: groupID, apiKeyID: apiKeyID, sessionHash: sessionHash}, true
}

func openAIWSSessionPreemptCacheHash(apiKeyID int64, sessionHash string) string {
	return fmt.Sprintf("%s%d:%s", openAIWSSessionPreemptCachePrefix, apiKeyID, strings.TrimSpace(sessionHash))
}

type openAIWSSessionPreemptEntry struct {
	generation uint64
	cancel     func()
}

type openAIWSSessionPreemptRegistry struct {
	mu     sync.Mutex
	next   uint64
	active map[openAIWSSessionPreemptKey]openAIWSSessionPreemptEntry
}

func (r *openAIWSSessionPreemptRegistry) Begin(key openAIWSSessionPreemptKey, cancel func()) (cleanup func(), preemptedPrevious bool) {
	if r == nil || strings.TrimSpace(key.sessionHash) == "" {
		return func() {}, false
	}
	r.mu.Lock()
	if r.active == nil {
		r.active = make(map[openAIWSSessionPreemptKey]openAIWSSessionPreemptEntry)
	}
	r.next++
	generation := r.next
	previous, hadPrevious := r.active[key]
	r.active[key] = openAIWSSessionPreemptEntry{generation: generation, cancel: cancel}
	r.mu.Unlock()
	if hadPrevious && previous.cancel != nil {
		previous.cancel()
	}
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		current, ok := r.active[key]
		if ok && current.generation == generation {
			delete(r.active, key)
		}
	}, hadPrevious
}

func (s *OpenAIGatewayService) beginOpenAIWSSessionPreemptContext(
	ctx context.Context,
	account *Account,
	groupID, apiKeyID int64,
	sessionHash string,
	httpIngressWSOneShot bool,
) (context.Context, func(), bool, bool) {
	return s.beginOpenAIWSSessionPreemptContextScoped(
		ctx,
		account,
		groupID,
		apiKeyID,
		sessionHash,
		sessionHash,
		httpIngressWSOneShot,
	)
}

// beginOpenAIWSSessionPreemptContextScoped separates the transport claim
// scope from the sticky-state key.  Codex root/subagent threads can share one
// session identity, so their live WebSocket ownership must be independent;
// state cleanup remains session-level only when the claim itself is
// session-scoped.
func (s *OpenAIGatewayService) beginOpenAIWSSessionPreemptContextScoped(
	ctx context.Context,
	account *Account,
	groupID, apiKeyID int64,
	preemptSessionHash string,
	stateSessionHash string,
	httpIngressWSOneShot bool,
) (context.Context, func(), bool, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || account == nil || !account.IsOpenAIOAuthLike() || httpIngressWSOneShot {
		return ctx, func() {}, false, false
	}
	preemptSessionHash = strings.TrimSpace(preemptSessionHash)
	stateSessionHash = strings.TrimSpace(stateSessionHash)
	if stateSessionHash == "" {
		stateSessionHash = preemptSessionHash
	}
	key, ok := newOpenAIWSSessionPreemptKey(groupID, apiKeyID, preemptSessionHash)
	if !ok {
		return ctx, func() {}, false, false
	}

	preemptCtx, cancel := context.WithCancelCause(ctx)
	ownerToken := uuid.NewString()
	var preemptOnce sync.Once
	preempt := func() {
		preemptOnce.Do(func() {
			if stateSessionHash != "" && preemptSessionHash == stateSessionHash {
				if stateStore := s.getOpenAIWSStateStore(); stateStore != nil {
					stateStore.DeleteSessionTurnState(key.groupID, stateSessionHash)
					stateStore.DeleteSessionConn(key.groupID, stateSessionHash)
				}
			}
			cancel(errOpenAIWSSessionPreempted)
		})
	}
	previousRemoteOwner, remoteClaimed := s.claimOpenAIWSSessionPreemptOwner(ctx, key, ownerToken)
	preemptedPrevious := remoteClaimed && previousRemoteOwner != "" && previousRemoteOwner != ownerToken
	cleanupLocal, hadLocalPrevious := s.openaiWSSessionPreemptions.Begin(key, preempt)
	preemptedPrevious = preemptedPrevious || hadLocalPrevious
	stopWatch := func() {}
	if remoteClaimed {
		stopWatch = s.watchOpenAIWSSessionPreemptOwner(preemptCtx, key, ownerToken, preempt)
	}

	return preemptCtx, func() {
		stopWatch()
		cleanupLocal()
		if remoteClaimed {
			s.releaseOpenAIWSSessionPreemptOwner(context.Background(), key, ownerToken)
		}
		cancel(nil)
	}, true, preemptedPrevious
}

func (s *OpenAIGatewayService) openAIWSSessionPreemptionCache() OpenAIWSSessionPreemptionCache {
	if s == nil || s.cache == nil {
		return nil
	}
	cache, _ := s.cache.(OpenAIWSSessionPreemptionCache)
	return cache
}

func (s *OpenAIGatewayService) claimOpenAIWSSessionPreemptOwner(ctx context.Context, key openAIWSSessionPreemptKey, ownerToken string) (string, bool) {
	cache := s.openAIWSSessionPreemptionCache()
	if cache == nil || strings.TrimSpace(ownerToken) == "" {
		return "", false
	}
	cacheCtx, cancel := context.WithTimeout(ctx, openAIWSStateStoreRedisTimeout)
	defer cancel()
	previous, err := cache.ClaimOpenAIResponsesSessionWindow(
		cacheCtx,
		key.groupID,
		openAIWSSessionPreemptCacheHash(key.apiKeyID, key.sessionHash),
		[]byte(strings.TrimSpace(ownerToken)),
		openAIWSSessionPreemptOwnerTTL,
	)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(previous)), true
}

func (s *OpenAIGatewayService) releaseOpenAIWSSessionPreemptOwner(ctx context.Context, key openAIWSSessionPreemptKey, ownerToken string) {
	cache := s.openAIWSSessionPreemptionCache()
	if cache == nil || strings.TrimSpace(ownerToken) == "" {
		return
	}
	cacheCtx, cancel := context.WithTimeout(ctx, openAIWSStateStoreRedisTimeout)
	defer cancel()
	_, _ = cache.CompareAndDeleteOpenAIResponsesSessionWindow(
		cacheCtx,
		key.groupID,
		openAIWSSessionPreemptCacheHash(key.apiKeyID, key.sessionHash),
		[]byte(strings.TrimSpace(ownerToken)),
	)
}

func (s *OpenAIGatewayService) watchOpenAIWSSessionPreemptOwner(ctx context.Context, key openAIWSSessionPreemptKey, ownerToken string, onLost func()) func() {
	cache := s.openAIWSSessionPreemptionCache()
	if cache == nil || onLost == nil || strings.TrimSpace(ownerToken) == "" {
		return func() {}
	}
	stopCh := make(chan struct{})
	var once sync.Once
	go func() {
		ticker := time.NewTicker(openAIWSSessionPreemptWatchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				cacheCtx, cancel := context.WithTimeout(context.Background(), openAIWSStateStoreRedisTimeout)
				owned, err := cache.CompareAndRefreshOpenAIResponsesSessionWindow(
					cacheCtx,
					key.groupID,
					openAIWSSessionPreemptCacheHash(key.apiKeyID, key.sessionHash),
					[]byte(strings.TrimSpace(ownerToken)),
					openAIWSSessionPreemptOwnerTTL,
				)
				cancel()
				if err == nil && !owned {
					onLost()
					return
				}
			}
		}
	}()
	return func() { once.Do(func() { close(stopCh) }) }
}

func isOpenAIWSSessionPreempted(ctx context.Context) bool {
	return ctx != nil && errors.Is(context.Cause(ctx), errOpenAIWSSessionPreempted)
}

func IsOpenAIWSSessionPreemptedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errOpenAIWSSessionPreempted) {
		return true
	}
	var fallbackErr *openAIWSFallbackError
	return errors.As(err, &fallbackErr) && fallbackErr != nil && strings.TrimPrefix(strings.TrimSpace(fallbackErr.Reason), "prewarm_") == "session_preempted"
}
