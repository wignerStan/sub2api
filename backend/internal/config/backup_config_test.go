//go:build unit

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeBackupProxyURL(t *testing.T) {
	t.Parallel()

	// 空 = 直连
	got, err := normalizeBackupProxyURL("")
	require.NoError(t, err)
	require.Empty(t, got)

	got, err = normalizeBackupProxyURL("   ")
	require.NoError(t, err)
	require.Empty(t, got)

	// socks5 → socks5h（DNS 走代理）
	got, err = normalizeBackupProxyURL("socks5://127.0.0.1:1083")
	require.NoError(t, err)
	require.Equal(t, "socks5h://127.0.0.1:1083", got)

	// http 代理保持原样
	got, err = normalizeBackupProxyURL("  http://127.0.0.1:8080 ")
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:8080", got)

	// 非法 scheme / 缺 host：fail-fast
	for _, raw := range []string{"ftp://127.0.0.1:21", "socks5://", "://bad"} {
		_, err := normalizeBackupProxyURL(raw)
		require.Error(t, err, raw)
	}
}
