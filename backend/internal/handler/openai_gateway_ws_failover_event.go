package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	coderws "github.com/coder/websocket"
)

const (
	openAIWSFailoverErrorWriteTimeout  = 2 * time.Second
	openAIWSFailoverErrorBodyMaxBytes  = 64 * 1024
	openAIWSFailoverRetryAfterMaxBytes = 128
)

type openAIWSFailoverErrorBody struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type openAIWSFailoverUpstreamEnvelope struct {
	fields     map[string]json.RawMessage
	errorBody  json.RawMessage
	retryAfter string
	message    string
}

// writeOpenAIWSFailoverErrorEvent converts the final hidden failover
// failure back into the Responses WebSocket error contract before the
// closing handshake. Codex maps a type=error frame with a root HTTP
// status into its normal HTTP/rate-limit handling; a close frame alone
// is always reported as an interrupted stream and retried.
func writeOpenAIWSFailoverErrorEvent(
	conn *coderws.Conn,
	failoverErr *service.UpstreamFailoverError,
	status int,
	errorType string,
	errorCode string,
	message string,
) bool {
	if conn == nil {
		return false
	}
	payload := buildOpenAIWSFailoverErrorEvent(failoverErr, status, errorType, errorCode, message)
	if len(payload) == 0 {
		return false
	}
	writeCtx, cancel := context.WithTimeout(context.Background(), openAIWSFailoverErrorWriteTimeout)
	defer cancel()
	return conn.Write(writeCtx, coderws.MessageText, payload) == nil
}

func buildOpenAIWSFailoverErrorEvent(
	failoverErr *service.UpstreamFailoverError,
	status int,
	errorType string,
	errorCode string,
	message string,
) []byte {
	if status < http.StatusBadRequest || status > 599 {
		status = http.StatusBadGateway
	}
	errorType = strings.TrimSpace(errorType)
	if errorType == "" {
		errorType = "upstream_error"
	}
	errorCode = strings.TrimSpace(errorCode)
	if errorCode == "" || (status == http.StatusTooManyRequests && errorCode == "upstream_ws_failover_exhausted") {
		if status == http.StatusTooManyRequests {
			errorCode = "rate_limit_exceeded"
		} else {
			errorCode = "upstream_ws_failover_exhausted"
		}
	}
	message = strings.TrimSpace(message)
	if message == "" {
		message = "upstream websocket proxy failed"
	}

	upstream := decodeOpenAIWSFailoverUpstreamEnvelope(failoverErr)
	fields := upstream.fields
	errorBody := upstream.errorBody
	if len(errorBody) == 0 {
		if upstream.message != "" {
			message = upstream.message
		}
		fallbackBody, err := json.Marshal(openAIWSFailoverErrorBody{
			Type:    errorType,
			Code:    errorCode,
			Message: message,
		})
		if err != nil {
			return nil
		}
		errorBody = fallbackBody
		fields = make(map[string]json.RawMessage)
	}
	if fields == nil {
		fields = make(map[string]json.RawMessage)
	}

	// Preserve the provider's original nested error object and any
	// non-header envelope metadata, but make the transport contract
	// unambiguous for Codex. Keeping both status and status_code would be
	// rejected by serde as a duplicate aliased field.
	fields["type"] = json.RawMessage(`"error"`)
	fields["status"] = json.RawMessage(strconv.Itoa(status))
	delete(fields, "status_code")
	fields["error"] = append(json.RawMessage(nil), errorBody...)

	if headers := openAIWSFailoverErrorHeaders(failoverErr, upstream.retryAfter); len(headers) > 0 {
		headerBody, err := json.Marshal(headers)
		if err != nil {
			return nil
		}
		fields["headers"] = headerBody
	} else {
		delete(fields, "headers")
	}

	payload, err := json.Marshal(fields)
	if err != nil {
		return nil
	}
	return payload
}

func decodeOpenAIWSFailoverUpstreamEnvelope(failoverErr *service.UpstreamFailoverError) openAIWSFailoverUpstreamEnvelope {
	var decoded openAIWSFailoverUpstreamEnvelope
	if failoverErr == nil {
		return decoded
	}
	body := bytes.TrimSpace(failoverErr.ResponseBody)
	if len(body) == 0 || len(body) > openAIWSFailoverErrorBodyMaxBytes || !json.Valid(body) {
		return decoded
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return decoded
	}
	decoded.message = openAIWSFailoverMessageFromFields(fields)
	decoded.retryAfter = openAIWSRetryAfterFromFields(fields)

	errorBody := bytes.TrimSpace(fields["error"])
	if len(errorBody) == 0 || errorBody[0] != '{' {
		return decoded
	}
	var errorFields map[string]json.RawMessage
	if err := json.Unmarshal(errorBody, &errorFields); err != nil || len(errorFields) == 0 {
		return decoded
	}

	decoded.fields = fields
	decoded.errorBody = append(json.RawMessage(nil), errorBody...)
	return decoded
}

func openAIWSFailoverMessageFromFields(fields map[string]json.RawMessage) string {
	if len(fields) == 0 {
		return ""
	}
	if errorBody := bytes.TrimSpace(fields["error"]); len(errorBody) > 0 {
		if errorBody[0] == '{' {
			var errorFields map[string]json.RawMessage
			if json.Unmarshal(errorBody, &errorFields) == nil {
				if message := openAIWSJSONString(errorFields["message"]); message != "" {
					return message
				}
			}
		} else if message := openAIWSJSONString(errorBody); message != "" {
			return message
		}
	}
	for _, key := range []string{"detail", "message"} {
		if message := openAIWSJSONString(fields[key]); message != "" {
			return message
		}
	}
	return ""
}

func openAIWSRetryAfterFromFields(fields map[string]json.RawMessage) string {
	headersBody := bytes.TrimSpace(fields["headers"])
	if len(headersBody) == 0 || headersBody[0] != '{' {
		return ""
	}
	var headers map[string]json.RawMessage
	if json.Unmarshal(headersBody, &headers) != nil {
		return ""
	}
	for key, rawValue := range headers {
		if strings.EqualFold(strings.TrimSpace(key), "Retry-After") {
			return openAIWSJSONScalar(rawValue)
		}
	}
	return ""
}

func openAIWSFailoverErrorHeaders(failoverErr *service.UpstreamFailoverError, eventRetryAfter string) map[string]string {
	candidates := []string{eventRetryAfter}
	if failoverErr != nil && failoverErr.ResponseHeaders != nil {
		candidates = append(candidates, failoverErr.ResponseHeaders.Get("Retry-After"))
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if isSafeOpenAIWSRetryAfter(candidate) {
			return map[string]string{"retry-after": candidate}
		}
	}
	return nil
}

func isSafeOpenAIWSRetryAfter(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > openAIWSFailoverRetryAfterMaxBytes || strings.ContainsAny(value, "\r\n") {
		return false
	}
	if _, err := strconv.ParseUint(value, 10, 63); err == nil {
		return true
	}
	_, err := http.ParseTime(value)
	return err == nil
}

func openAIWSJSONString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func openAIWSJSONScalar(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}
