package service

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewOpenAIWSDialRateLimitFailoverErrorPreservesHandshakePayload(t *testing.T) {
	body := []byte(`{"error":{"type":"usage_limit_reached","message":"quota exhausted","resets_in_seconds":1800}}`)
	headers := http.Header{
		"Retry-After":  []string{"1800"},
		"X-Request-Id": []string{"req_quota"},
	}
	dialErr := &openAIWSDialError{
		StatusCode:      http.StatusTooManyRequests,
		ResponseHeaders: headers,
		ResponseBody:    body,
		Err:             errors.New("upstream rejected websocket upgrade"),
	}

	gateway := &OpenAIGatewayService{}
	failoverErr := gateway.newOpenAIWSDialRateLimitFailoverError(nil, dialErr, dialErr.Error())

	require.NotNil(t, failoverErr)
	require.Equal(t, http.StatusTooManyRequests, failoverErr.StatusCode)
	require.Equal(t, body, failoverErr.ResponseBody)
	require.Equal(t, "1800", failoverErr.ResponseHeaders.Get("Retry-After"))
	require.Equal(t, "req_quota", failoverErr.ResponseHeaders.Get("X-Request-Id"))

	// Failover owns a cloned header map so later dial cleanup cannot
	// mutate the terminal error exposed to the client.
	headers.Set("Retry-After", "1")
	require.Equal(t, "1800", failoverErr.ResponseHeaders.Get("Retry-After"))
}

func TestNewOpenAIWSDialRateLimitFailoverErrorHandlesMissingDialMetadata(t *testing.T) {
	gateway := &OpenAIGatewayService{}
	failoverErr := gateway.newOpenAIWSDialRateLimitFailoverError(nil, nil, "quota exhausted")

	require.NotNil(t, failoverErr)
	require.Equal(t, http.StatusTooManyRequests, failoverErr.StatusCode)
	require.Nil(t, failoverErr.ResponseBody)
	require.Empty(t, failoverErr.ResponseHeaders)
}
