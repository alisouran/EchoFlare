package main

// util.go — miscellaneous helpers used across bot command handlers.

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	tb "gopkg.in/telebot.v3"
)

func tailFile(path string, n int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read %q: %w", path, err)
	}
	if len(lines) == 0 {
		return "", nil
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}

func splitTelegramMessage(text string, limit int) []string {
	if len(text) <= limit {
		return []string{text}
	}
	var parts []string
	for len(text) > limit {
		parts = append(parts, text[:limit])
		text = text[limit:]
	}
	if text != "" {
		parts = append(parts, text)
	}
	return parts
}

// isBotBlocked returns true when the Telegram API error indicates that the
// user has blocked the bot, the chat was not found, or the account is deleted.
// These are expected conditions during a broadcast and should be skipped silently.
func isBotBlocked(err error) bool {
	if err == nil {
		return false
	}
	// telebot v3 exposes tb.ErrBlockedByUser for the most common case.
	if errors.Is(err, tb.ErrBlockedByUser) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "blocked by the user") ||
		strings.Contains(s, "chat not found") ||
		strings.Contains(s, "user is deactivated") ||
		strings.Contains(s, "bot was kicked") ||
		strings.Contains(s, "forbidden")
}

// formatInt formats an integer with comma thousands separators (e.g. 1247 → "1,247").
func formatInt(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
