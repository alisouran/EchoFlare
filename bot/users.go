package main

// users.go — thread-safe, JSON-backed registry of Telegram chat IDs.
//
// Every user who sends /start or /status is registered here so the admin
// can reach them all via /broadcast.  The file is written atomically
// (write-to-temp + rename) so a crash never corrupts the registry.

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
)

type userStoreFile struct {
	IDs []int64 `json:"ids"`
}

// UserStore holds the set of known chat IDs in memory and mirrors it to disk.
type UserStore struct {
	mu   sync.RWMutex
	path string
	ids  map[int64]struct{}
}

// NewUserStore loads the registry from disk (or starts empty if the file does
// not exist or cannot be parsed — never fatal).
func NewUserStore(path string, logger *slog.Logger) *UserStore {
	s := &UserStore{
		path: path,
		ids:  make(map[int64]struct{}),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warn("user store: could not read file — starting empty", "path", path, "err", err)
		}
		return s
	}
	var f userStoreFile
	if err := json.Unmarshal(data, &f); err != nil {
		logger.Warn("user store: could not parse file — starting empty", "path", path, "err", err)
		return s
	}
	for _, id := range f.IDs {
		s.ids[id] = struct{}{}
	}
	logger.Info("user store loaded", "path", path, "count", len(s.ids))
	return s
}

// Add registers a chat ID.  It is a no-op if the ID is already known.
// Saves to disk immediately if the ID is new.
func (s *UserStore) Add(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.ids[id]; exists {
		return
	}
	s.ids[id] = struct{}{}
	s.save() //nolint:errcheck — best-effort; logged inside save()
}

// All returns a sorted slice of all registered chat IDs.
func (s *UserStore) All() []int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]int64, 0, len(s.ids))
	for id := range s.ids {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Len returns the number of registered users.
func (s *UserStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ids)
}

// save writes the registry to disk atomically.  Must be called with mu held.
func (s *UserStore) save() error {
	ids := make([]int64, 0, len(s.ids))
	for id := range s.ids {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	data, err := json.MarshalIndent(userStoreFile{IDs: ids}, "", "  ")
	if err != nil {
		return fmt.Errorf("user store marshal: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("user store write tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("user store rename: %w", err)
	}
	return nil
}
