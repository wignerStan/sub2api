//go:build unit

package repository

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestS3BackupStore_UploadFile(t *testing.T) {
	var received []byte
	var receivedLength int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		receivedLength = r.ContentLength
		var err error
		received, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := newS3Client(context.Background(), s3ClientParams{
		Endpoint:        server.URL,
		Region:          "auto",
		AccessKeyID:     "test-ak",
		SecretAccessKey: "test-sk",
		ForcePathStyle:  true,
	})
	require.NoError(t, err)

	content := []byte("streamed backup payload")
	filePath := t.TempDir() + "/part.gz"
	require.NoError(t, os.WriteFile(filePath, content, 0o600))

	store := &S3BackupStore{client: client, bucket: "backup-bucket"}
	size, err := store.UploadFile(context.Background(), "backup/part-1", filePath, "application/octet-stream")
	require.NoError(t, err)
	require.Equal(t, int64(len(content)), size)
	require.Equal(t, int64(len(content)), receivedLength)
	require.Equal(t, content, received)
}

func TestS3ProxyFunc(t *testing.T) {
	t.Parallel()

	// 空代理：nil 表示直连。
	proxyFn, err := s3ProxyFunc("")
	require.NoError(t, err)
	require.Nil(t, proxyFn)

	proxyFn, err = s3ProxyFunc("   ")
	require.NoError(t, err)
	require.Nil(t, proxyFn)

	// socks5 代理：解析为配置的 URL（socks5h 由 proxyurl 层归一化），
	// net/http 对 https 目标自动走隧道并远端解析域名。
	proxyFn, err = s3ProxyFunc("socks5h://127.0.0.1:1083")
	require.NoError(t, err)
	require.NotNil(t, proxyFn)

	req, err := http.NewRequest(http.MethodGet, "https://example-account.r2.cloudflarestorage.com/bucket/key", nil)
	require.NoError(t, err)
	got, err := proxyFn(req)
	require.NoError(t, err)
	require.Equal(t, "socks5h://127.0.0.1:1083", got.String())

	// 非法 URL：fail-fast，不回退直连。
	_, err = s3ProxyFunc("://bad")
	require.Error(t, err)
	_, err = s3ProxyFunc("not a url")
	require.Error(t, err)
}
