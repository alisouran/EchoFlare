package main

// logger.go — structured JSON logger setup for echocatcher.

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

// newLogger creates an slog.Logger that writes JSON to both stdout and the
// specified file (append mode).  Uses io.MultiWriter so each record is fanned
// out atomically to both destinations.
func newLogger(logPath string) (*slog.Logger, *os.File, error) {
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file %q: %w", logPath, err)
	}
	multi := io.MultiWriter(os.Stdout, lf)
	logger := slog.New(slog.NewJSONHandler(multi, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	return logger, lf, nil
}
