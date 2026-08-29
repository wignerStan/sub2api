package openai_ws_v2

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	coderws "github.com/coder/websocket"
)

type quotaFilterFrame struct {
	msgType coderws.MessageType
	payload []byte
	err     error
}

type quotaFilterFrameConn struct {
	frames      []quotaFilterFrame
	writes      []quotaFilterFrame
	closeCalled bool
}

func (c *quotaFilterFrameConn) ReadFrame(context.Context) (coderws.MessageType, []byte, error) {
	if len(c.frames) == 0 {
		return coderws.MessageText, nil, io.EOF
	}
	frame := c.frames[0]
	c.frames = c.frames[1:]
	return frame.msgType, frame.payload, frame.err
}

func (c *quotaFilterFrameConn) WriteFrame(_ context.Context, msgType coderws.MessageType, payload []byte) error {
	c.writes = append(c.writes, quotaFilterFrame{msgType: msgType, payload: append([]byte(nil), payload...)})
	return nil
}

func (c *quotaFilterFrameConn) Close() error {
	c.closeCalled = true
	return nil
}

func quotaFilterEventPayload(eventType string) []byte {
	payload, err := json.Marshal(map[string]string{"type": eventType})
	if err != nil {
		panic(err)
	}
	return payload
}

func TestCodexQuotaFilteringFrameConnDropsRateLimitEvents(t *testing.T) {
	inner := &quotaFilterFrameConn{frames: []quotaFilterFrame{
		{msgType: coderws.MessageText, payload: quotaFilterEventPayload("codex.rate_limits")},
		{msgType: coderws.MessageText, payload: quotaFilterEventPayload("response.created")},
	}}
	filtered := withoutCodexQuotaEvents(inner)

	msgType, payload, err := filtered.ReadFrame(context.Background())
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if msgType != coderws.MessageText {
		t.Fatalf("expected text frame, got %v", msgType)
	}
	if got, want := string(payload), string(quotaFilterEventPayload("response.created")); got != want {
		t.Fatalf("expected ordinary event after quota drop, got %s", got)
	}
}

func TestCodexQuotaFilteringFrameConnKeepsBinaryAndSimilarEvents(t *testing.T) {
	binaryQuota := quotaFilterEventPayload("codex.rate_limits")
	similarText := quotaFilterEventPayload("codex.rate_limits.updated")
	inner := &quotaFilterFrameConn{frames: []quotaFilterFrame{
		{msgType: coderws.MessageBinary, payload: binaryQuota},
		{msgType: coderws.MessageText, payload: similarText},
	}}
	filtered := withoutCodexQuotaEvents(inner)

	msgType, payload, err := filtered.ReadFrame(context.Background())
	if err != nil {
		t.Fatalf("unexpected binary read error: %v", err)
	}
	if msgType != coderws.MessageBinary || string(payload) != string(binaryQuota) {
		t.Fatalf("expected binary frame passthrough, got type=%v payload=%s", msgType, payload)
	}

	msgType, payload, err = filtered.ReadFrame(context.Background())
	if err != nil {
		t.Fatalf("unexpected text read error: %v", err)
	}
	if msgType != coderws.MessageText || string(payload) != string(similarText) {
		t.Fatalf("expected non-matching text event passthrough, got type=%v payload=%s", msgType, payload)
	}
}

func TestCodexQuotaFilteringFrameConnPropagatesReadError(t *testing.T) {
	wantErr := errors.New("upstream closed")
	inner := &quotaFilterFrameConn{frames: []quotaFilterFrame{
		{msgType: coderws.MessageText, payload: quotaFilterEventPayload("codex.rate_limits")},
		{msgType: coderws.MessageText, err: wantErr},
	}}
	filtered := withoutCodexQuotaEvents(inner)

	_, _, err := filtered.ReadFrame(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
}

func TestCodexQuotaFilteringFrameConnDelegatesWriteAndClose(t *testing.T) {
	inner := &quotaFilterFrameConn{}
	filtered := withoutCodexQuotaEvents(inner)
	payload := quotaFilterEventPayload("response.create")

	if err := filtered.WriteFrame(context.Background(), coderws.MessageText, payload); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if len(inner.writes) != 1 || string(inner.writes[0].payload) != string(payload) {
		t.Fatalf("expected delegated write, got %#v", inner.writes)
	}
	if err := filtered.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
	if !inner.closeCalled {
		t.Fatal("expected delegated close")
	}
}

func TestWithoutCodexQuotaEventsPreservesNil(t *testing.T) {
	if got := withoutCodexQuotaEvents(nil); got != nil {
		t.Fatalf("expected nil passthrough, got %#v", got)
	}
}
