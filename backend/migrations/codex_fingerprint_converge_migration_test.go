package migrations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigration227ConvergesAllOpenAIOAuthNotOnlyEnabledModes(t *testing.T) {
	content, err := FS.ReadFile("227_converge_codex_fingerprint.sql")
	require.NoError(t, err)
	sql := string(content)
	require.Contains(t, sql, "codex_fingerprint_mode")
	require.Contains(t, sql, "session")
	require.Contains(t, sql, "platform = 'openai'")
	require.Contains(t, sql, "type = 'oauth'")
	require.Contains(t, sql, "gen_random_uuid()")
	require.NotContains(t, sql, "IN ('device', 'session', 'full')")
	require.Contains(t, sql, "NOT IN ('session')")
}

func TestMigration225LeftOffAccountsUnseeded(t *testing.T) {
	content, err := FS.ReadFile("225_backfill_codex_fingerprint_seed.sql")
	require.NoError(t, err)
	sql := string(content)
	require.Contains(t, sql, "IN ('device', 'session', 'full')")
}
