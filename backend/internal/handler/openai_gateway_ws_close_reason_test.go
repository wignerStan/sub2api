package handler

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestTruncateOpenAIWSCloseReason(t *testing.T) {
	t.Run("ascii", func(t *testing.T) {
		got := truncateOpenAIWSCloseReason(strings.Repeat("a", openAIWSCloseReasonMaxBytes+10))
		require.Len(t, got, openAIWSCloseReasonMaxBytes)
	})

	t.Run("utf8", func(t *testing.T) {
		got := truncateOpenAIWSCloseReason(strings.Repeat("🙂", 40))
		require.LessOrEqual(t, len(got), openAIWSCloseReasonMaxBytes)
		require.True(t, utf8.ValidString(got))
		require.Equal(t, 30, utf8.RuneCountInString(got))
	})

	t.Run("invalid utf8", func(t *testing.T) {
		got := truncateOpenAIWSCloseReason(string([]byte{'a', 0xff, 'b'}))
		require.True(t, utf8.ValidString(got))
		require.Equal(t, "a�b", got)
	})

	t.Run("trim", func(t *testing.T) {
		require.Equal(t, "close reason", truncateOpenAIWSCloseReason("  close reason  "))
	})
}
