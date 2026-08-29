package openai_ws_v2

import (
	"context"
	"strings"

	coderws "github.com/coder/websocket"
	"github.com/tidwall/gjson"
)

// withoutCodexQuotaEvents removes account-scoped rate-limit snapshots from the
// upstream-to-client relay. The gateway still keeps handshake/error metadata
// for internal scheduling; only successful codex.rate_limits status updates are
// hidden from the downstream Codex client.
func withoutCodexQuotaEvents(conn FrameConn) FrameConn {
	if conn == nil {
		return nil
	}
	return &codexQuotaFilteringFrameConn{FrameConn: conn}
}

type codexQuotaFilteringFrameConn struct {
	FrameConn
}

var _ FrameConn = (*codexQuotaFilteringFrameConn)(nil)

func (c *codexQuotaFilteringFrameConn) ReadFrame(ctx context.Context) (coderws.MessageType, []byte, error) {
	for {
		msgType, payload, err := c.FrameConn.ReadFrame(ctx)
		if err != nil {
			return msgType, payload, err
		}
		if msgType == coderws.MessageText && isCodexQuotaEvent(payload) {
			continue
		}
		return msgType, payload, nil
	}
}

func isCodexQuotaEvent(payload []byte) bool {
	return strings.TrimSpace(gjson.GetBytes(payload, "type").String()) == "codex.rate_limits"
}
