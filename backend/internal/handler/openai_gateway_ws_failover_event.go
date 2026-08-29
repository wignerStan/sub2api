package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	coderws "github.com/coder/websocket"
)

const openAIWSFailoverErrorWriteTimeout = 2 * time.Second

type openAIWSFailoverErrorBody struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type openAIWSFailoverErrorEvent struct {
	Type    string                    `json:"type"`
	Status  int                       `json:"status"`
	Error   openAIWSFailoverErrorBody `json:"error"`
	Headers map[string]string         `json:"headers,omitempty"`
}

func writeOpenAIWSFailoverErrorEvent(
	conn *coderws.Conn,
	failoverErr *service.UpstreamFailoverError,
	status int,
	errorType string,
	errorCode string,
	message string,
) {
	if conn == nil {
		return
	}
	if status < http.StatusBadRequest || status > 599 {
		status = http.StatusBadGateway
	}
	errorType = strings.TrimSpace(errorType)
	if errorType == "" {
		errorType = "upstream_error"
	}
	errorCode = strings.TrimSpace(errorCode)
	if errorCode == "" {
		errorCode = "upstream_ws_failover_exhausted"
	}
	message = strings.TrimSpace(message)
	if message == "" {
		message = "upstream websocket proxy failed"
	}

	event := openAIWSFailoverErrorEvent{
		Type:   "error",
		Status: status,
		Error: openAIWSFailoverErrorBody{
			Type:    errorType,
			Code:    errorCode,
			Message: message,
		},
		Headers: openAIWSFailoverErrorHeaders(failoverErr),
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}

	writeCtx, cancel := context.WithTimeout(context.Background(), openAIWSFailoverErrorWriteTimeout)
	defer cancel()
	_ = conn.Write(writeCtx, coderws.MessageText, payload)
}

func openAIWSFailoverErrorHeaders(failoverErr *service.UpstreamFailoverError) map[string]string {
	if failoverErr == nil || failoverErr.ResponseHeaders == nil {
		return nil
	}
	retryAfter := strings.TrimSpace(failoverErr.ResponseHeaders.Get("Retry-After"))
	if retryAfter == "" || len(retryAfter) > 128 || strings.ContainsAny(retryAfter, "\r\n") || !isSafeRetryAfter(retryAfter) {
		return nil
	}
	return map[string]string{"retry-after": retryAfter}
}
