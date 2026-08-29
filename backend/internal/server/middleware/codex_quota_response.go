package middleware

import (
	"bufio"
	"net"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/util/responseheaders"
	"github.com/gin-gonic/gin"
)

// CodexQuotaResponseIsolation prevents an upstream account's quota snapshot
// from becoming the downstream Codex client's authoritative usage state. The
// gateway keeps the original upstream headers internally; only the final HTTP
// response writer is scrubbed before headers are committed.
func CodexQuotaResponseIsolation() gin.HandlerFunc {
	return func(c *gin.Context) {
		writer := &codexQuotaResponseWriter{ResponseWriter: c.Writer}
		c.Writer = writer
		defer writer.stripQuotaHeaders()
		c.Next()
	}
}

type codexQuotaResponseWriter struct {
	gin.ResponseWriter
}

var _ gin.ResponseWriter = (*codexQuotaResponseWriter)(nil)

func (w *codexQuotaResponseWriter) Unwrap() http.ResponseWriter {
	if w == nil {
		return nil
	}
	return w.ResponseWriter
}

func (w *codexQuotaResponseWriter) stripQuotaHeaders() {
	if w == nil || w.ResponseWriter == nil {
		return
	}
	responseheaders.StripCodexQuotaHeaders(w.Header())
}

func (w *codexQuotaResponseWriter) WriteHeader(code int) {
	w.stripQuotaHeaders()
	w.ResponseWriter.WriteHeader(code)
}

func (w *codexQuotaResponseWriter) WriteHeaderNow() {
	w.stripQuotaHeaders()
	w.ResponseWriter.WriteHeaderNow()
}

func (w *codexQuotaResponseWriter) Write(data []byte) (int, error) {
	w.stripQuotaHeaders()
	return w.ResponseWriter.Write(data)
}

func (w *codexQuotaResponseWriter) WriteString(data string) (int, error) {
	w.stripQuotaHeaders()
	return w.ResponseWriter.WriteString(data)
}

func (w *codexQuotaResponseWriter) Flush() {
	w.stripQuotaHeaders()
	w.ResponseWriter.Flush()
}

func (w *codexQuotaResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.stripQuotaHeaders()
	return w.ResponseWriter.Hijack()
}
