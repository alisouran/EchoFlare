// orchestrator-bot: Telegram remote control for a VPS running MasterDnsVPN and EchoCatcher.
//
// Access model:
//   Admin (owner_id in config) — full control: /scan, /toggle_vpn, /get_logs, /broadcast,
//                                               /update, /cmd
//   Public (anyone else)       — read-only: /status shows a friendly online/offline message
//
// Every user who interacts with the bot is registered in a JSON file (users_file) so
// the admin can reach them all via /broadcast.
//
// Configuration is read from a YAML file (default ./config.yaml, override via CONFIG env var).
//
// Usage (on the VPS):
//
//	CONFIG=/opt/dns-orchestrator/config.yaml ./orchestrator-bot
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tb "gopkg.in/telebot.v3"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type Config struct {
	Telegram TelegramConfig `yaml:"telegram"`
	Services ServicesConfig `yaml:"services"`
	Scanner  ScannerConfig  `yaml:"scanner"`
	Health   HealthConfig   `yaml:"health"`
}

type TelegramConfig struct {
	Token     string `yaml:"token"`
	OwnerID   int64  `yaml:"owner_id"`
	UsersFile string `yaml:"users_file"` // path to the persistent user registry
}

type ServicesConfig struct {
	VPN     string `yaml:"vpn"`
	Scanner string `yaml:"scanner"`
}

type ScannerConfig struct {
	LogFile string `yaml:"log_file"`
}

type HealthConfig struct {
	PingTarget    string        `yaml:"ping_target"`
	Interval      time.Duration `yaml:"interval"`
	LossThreshold int           `yaml:"loss_threshold"`
}

// loadConfig reads and parses the YAML configuration file.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	cfg := &Config{
		Services: ServicesConfig{
			VPN:     "masterdnsvpn.service",
			Scanner: "echocatcher.service",
		},
		Scanner: ScannerConfig{
			LogFile: "/var/log/echocatcher/working_dns.json",
		},
		Health: HealthConfig{
			PingTarget:    "8.8.8.8",
			Interval:      5 * time.Minute,
			LossThreshold: 60,
		},
		Telegram: TelegramConfig{
			UsersFile: "/opt/dns-orchestrator/users.json",
		},
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Telegram.Token == "" {
		return nil, fmt.Errorf("telegram.token must be set in config")
	}
	if cfg.Telegram.OwnerID == 0 {
		return nil, fmt.Errorf("telegram.owner_id must be set in config")
	}
	return cfg, nil
}

// ---------------------------------------------------------------------------
// UserStore — thread-safe, JSON-backed registry of chat IDs
//
// Every user who sends /start or /status is registered here so the admin
// can reach them all via /broadcast.  The file is written atomically
// (write-to-temp + rename) so a crash never corrupts the registry.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Service management helpers
// ---------------------------------------------------------------------------

func svcCmd(action, service string) error {
	out, err := exec.Command("sudo", "systemctl", action, service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %w — %s", action, service, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func svcStatus(service string) string {
	out, err := exec.Command("sudo", "systemctl", "is-active", service).Output()
	if err != nil {
		return strings.TrimSpace(string(out))
	}
	return strings.TrimSpace(string(out))
}

func svcStatusEmoji(state string) string {
	switch state {
	case "active":
		return "🟢 active"
	case "inactive":
		return "⚫ inactive"
	case "failed":
		return "🔴 failed"
	default:
		return "⚠️ " + state
	}
}

// ---------------------------------------------------------------------------
// Server stats (CPU + RAM from /proc — no external tools needed)
// ---------------------------------------------------------------------------

type cpuStat struct{ idle, total uint64 }

func readCPUStat() (cpuStat, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuStat{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			break
		}
		var vals [10]uint64
		for i := 1; i < len(fields) && i <= 10; i++ {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			vals[i-1] = v
		}
		idle := vals[3] + vals[4]
		total := uint64(0)
		for _, v := range vals {
			total += v
		}
		return cpuStat{idle: idle, total: total}, nil
	}
	return cpuStat{}, fmt.Errorf("/proc/stat: cpu line not found")
}

func serverStats() string {
	s1, err1 := readCPUStat()
	time.Sleep(500 * time.Millisecond)
	s2, err2 := readCPUStat()

	cpuStr := "N/A"
	if err1 == nil && err2 == nil {
		deltaIdle := s2.idle - s1.idle
		deltaTotal := s2.total - s1.total
		if deltaTotal > 0 {
			cpuPct := 100.0 * float64(deltaTotal-deltaIdle) / float64(deltaTotal)
			cpuStr = fmt.Sprintf("%.1f%%", cpuPct)
		}
	}

	ramStr := "N/A"
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var memTotal, memAvail uint64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseUint(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				memTotal = val
			case "MemAvailable:":
				memAvail = val
			}
		}
		if memTotal > 0 {
			used := memTotal - memAvail
			ramStr = fmt.Sprintf("%.1f GB / %.1f GB",
				float64(used)/1024/1024,
				float64(memTotal)/1024/1024,
			)
		}
	}

	return fmt.Sprintf("CPU: %s   RAM: %s", cpuStr, ramStr)
}

// ---------------------------------------------------------------------------
// Packet loss helper
// ---------------------------------------------------------------------------

var lossRe = regexp.MustCompile(`(\d+)%\s+packet loss`)

func packetLoss(target string) (int, error) {
	out, err := exec.Command("ping", "-c", "10", "-W", "1", target).CombinedOutput()
	matches := lossRe.FindSubmatch(out)
	if len(matches) < 2 {
		if err != nil {
			return 0, fmt.Errorf("ping %s: %w — %s", target, err, strings.TrimSpace(string(out)))
		}
		return 0, fmt.Errorf("ping %s: could not parse output", target)
	}
	pct, _ := strconv.Atoi(string(matches[1]))
	return pct, nil
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Scan result helpers
// ---------------------------------------------------------------------------

// countScanHits counts the number of successful resolver hits in the echocatcher
// log file by counting lines that contain the "dns_hit" event marker.
// Uses bytes to avoid a large string allocation for potentially big log files.
func countScanHits(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.Contains(line, []byte(`"dns_hit"`)) {
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// Phase 4 — Scan result helpers
// ---------------------------------------------------------------------------

// Hit represents a single successful resolver record from the echocatcher NDJSON log.
type Hit struct {
	TargetIP   string  `json:"target_ip"`
	LatencySec float64 `json:"latency_sec"`
}

// parseScanHits reads the echocatcher NDJSON log and returns all "dns_hit"
// records sorted by LatencySec ascending (fastest resolvers first).
func parseScanHits(path string) ([]Hit, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	var hits []Hit
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || !bytes.Contains(line, []byte(`"dns_hit"`)) {
			continue
		}
		var h Hit
		if err := json.Unmarshal(line, &h); err != nil {
			continue
		}
		if h.TargetIP != "" {
			hits = append(hits, h)
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].LatencySec < hits[j].LatencySec
	})
	return hits, nil
}

// generateMasterDNSVPNTOML takes the top 50 lowest-latency hits and builds a
// ready-to-paste TOML snippet for MasterDnsVPN.
//
// IPv6 addresses are enclosed in brackets to prevent MasterDnsVPN's TOML
// parser from crashing:
//
//	IPv4: "udp://8.8.8.8:53"
//	IPv6: "udp://[2001:db8::1]:53"
func generateMasterDNSVPNTOML(hits []Hit) string {
	top := hits
	if len(top) > 50 {
		top = top[:50]
	}
	var sb strings.Builder
	sb.WriteString("[Resolvers]\nList = [\n")
	for _, h := range top {
		ip := net.ParseIP(h.TargetIP)
		var entry string
		if ip != nil && ip.To4() == nil {
			entry = fmt.Sprintf(`    "udp://[%s]:53"`, h.TargetIP)
		} else {
			entry = fmt.Sprintf(`    "udp://%s:53"`, h.TargetIP)
		}
		sb.WriteString(entry + ",\n")
	}
	sb.WriteString("]\n")
	return sb.String()
}

// ---------------------------------------------------------------------------
// Broadcast helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Bot state
// ---------------------------------------------------------------------------

var (
	scanMu      sync.Mutex  // held for the duration of a /scan operation
	scanRunning atomic.Bool // true while a scan is in progress
)

// ---------------------------------------------------------------------------
// Health monitor
// ---------------------------------------------------------------------------

func healthMonitor(ctx context.Context, bot *tb.Bot, ownerID int64, cfg *Config, logger *slog.Logger) {
	ticker := time.NewTicker(cfg.Health.Interval)
	defer ticker.Stop()

	owner := &tb.Chat{ID: ownerID}

	for {
		select {
		case <-ticker.C:
			loss, err := packetLoss(cfg.Health.PingTarget)
			if err != nil {
				logger.Warn("health monitor ping error", "err", err)
				continue
			}
			logger.Info("health check", "target", cfg.Health.PingTarget, "loss_pct", loss)
			if loss >= cfg.Health.LossThreshold {
				msg := fmt.Sprintf(
					"⚠️ *High Packet Loss Detected!*\n%d%% loss to %s\n\nWould you like to run a new DNS scan? Use `/scan 5m`",
					loss, cfg.Health.PingTarget,
				)
				if _, err := bot.Send(owner, msg, tb.ModeMarkdown); err != nil {
					logger.Error("health alert send failed", "err", err)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	// ---- Logger ---------------------------------------------------------------
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// ---- Config ---------------------------------------------------------------
	cfgPath := os.Getenv("CONFIG")
	if cfgPath == "" {
		cfgPath = "config.yaml"
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		logger.Error("failed to load config", "path", cfgPath, "err", err)
		os.Exit(1)
	}
	logger.Info("config loaded", "config", cfgPath, "owner_id", cfg.Telegram.OwnerID)

	// ---- User registry --------------------------------------------------------
	users := NewUserStore(cfg.Telegram.UsersFile, logger)

	// ---- Telebot setup --------------------------------------------------------
	pref := tb.Settings{
		Token:  cfg.Telegram.Token,
		Poller: &tb.LongPoller{Timeout: 30 * time.Second},
	}
	bot, err := tb.NewBot(pref)
	if err != nil {
		logger.Error("failed to create bot", "err", err)
		os.Exit(1)
	}

	// ---- Auth helpers ---------------------------------------------------------
	// isAdmin returns true if the sender is the configured owner.
	isAdmin := func(c tb.Context) bool {
		return c.Sender().ID == cfg.Telegram.OwnerID
	}

	// adminOnly sends an access-denied reply and returns false for non-admins.
	// Usage:  if !adminOnly(c) { return nil }
	adminOnly := func(c tb.Context) bool {
		if isAdmin(c) {
			return true
		}
		logger.Info("access denied", "sender_id", c.Sender().ID, "cmd", c.Text())
		c.Send("⛔ Access Denied. You are not authorized.") //nolint:errcheck
		return false
	}

	// safeSend wraps bot.Send with error logging (used in goroutines where we
	// cannot return an error to the telebot framework).
	safeSend := func(dest tb.Recipient, text string, opts ...interface{}) {
		if _, err := bot.Send(dest, text, opts...); err != nil {
			logger.Error("send error", "err", err)
		}
	}

	// reply is a shorthand for sending to the current context's chat.
	reply := func(c tb.Context, text string) {
		if err := c.Send(text); err != nil {
			logger.Error("reply error", "err", err)
		}
	}

	// ---- Help text ------------------------------------------------------------
	adminHelpText := strings.Join([]string{
		"*🤖 Server Orchestrator Bot — Admin*",
		"",
		"*Admin Commands:*",
		"/status — full service states + CPU/RAM",
		"/scan <duration> — run DNS scan (e.g. `/scan 5m`)",
		"  Stops VPN → starts EchoCatcher → waits → sends results → restarts VPN",
		"  Delivers: `working_resolvers.json` + `masterdnsvpn_resolvers.toml` (top 50)",
		"/toggle\\_vpn — start or stop the VPN",
		"/get\\_logs — last 50 lines of VPN journal logs",
		"/broadcast <message> — send a message to all registered users",
		"/update — pull latest code from GitHub and rebuild all binaries",
		"/cmd <command> — run a shell command on the server (5-min timeout)",
		"/help — show this message",
	}, "\n")

	publicHelpText := strings.Join([]string{
		"👋 *Welcome!*",
		"",
		"This bot monitors a network optimisation service.",
		"",
		"/status — check if the service is online",
		"/help   — show this message",
	}, "\n")

	// ---- /start and /help -----------------------------------------------------
	// Both handlers register the user and show role-appropriate help.
	handleHelp := func(c tb.Context) error {
		users.Add(c.Sender().ID)
		if isAdmin(c) {
			return c.Send(adminHelpText, tb.ModeMarkdown)
		}
		return c.Send(publicHelpText, tb.ModeMarkdown)
	}
	bot.Handle("/start", handleHelp)
	bot.Handle("/help", handleHelp)

	// ---- /status — dual view --------------------------------------------------
	bot.Handle("/status", func(c tb.Context) error {
		users.Add(c.Sender().ID)

		if !isAdmin(c) {
			// Public view: no service names, no resource metrics.
			if scanRunning.Load() {
				return c.Send("📡 Server is currently scanning for better routes.\nVPN is temporarily offline.")
			}
			if svcStatus(cfg.Services.VPN) == "active" {
				return c.Send("✅ System is online and stable.")
			}
			return c.Send("⚠️ Service is currently undergoing maintenance.")
		}

		// Admin view: full technical detail.
		vpnState := svcStatus(cfg.Services.VPN)
		scanState := svcStatus(cfg.Services.Scanner)
		stats := serverStats()

		text := fmt.Sprintf(
			"*Server Status*\n\n"+
				"VPN (%s):\n  %s\n\n"+
				"Scanner (%s):\n  %s\n\n"+
				"Resources:\n  %s\n\n"+
				"Registered users: %d",
			cfg.Services.VPN, svcStatusEmoji(vpnState),
			cfg.Services.Scanner, svcStatusEmoji(scanState),
			stats,
			users.Len(),
		)
		return c.Send(text, tb.ModeMarkdown)
	})

	// ---- /scan <duration> — admin only ----------------------------------------
	bot.Handle("/scan", func(c tb.Context) error {
		if !adminOnly(c) {
			return nil
		}

		args := c.Args()
		if len(args) == 0 {
			reply(c, "Usage: /scan <duration>  (e.g. /scan 5m or /scan 10m)")
			return nil
		}

		dur, err := time.ParseDuration(args[0])
		if err != nil || dur <= 0 {
			reply(c, fmt.Sprintf("Invalid duration %q. Example: /scan 5m", args[0]))
			return nil
		}

		if !scanMu.TryLock() {
			reply(c, "⏳ A scan is already running. Please wait for it to finish.")
			return nil
		}
		scanRunning.Store(true)

		reply(c, fmt.Sprintf("🔍 Starting DNS scan for %s...\nStopping VPN first.", dur))

		destChat := c.Chat()
		adminChat := &tb.Chat{ID: cfg.Telegram.OwnerID}

		send := func(text string) {
			safeSend(destChat, text)
		}

		go func() {
			defer func() {
				scanRunning.Store(false)
				scanMu.Unlock()
			}()

			// Step 1: Stop VPN.
			if err := svcCmd("stop", cfg.Services.VPN); err != nil {
				errMsg := err.Error()
				if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "Unit") {
					send(fmt.Sprintf("❌ Service %q not found.\nVerify the service name in config.yaml and re-run install.sh.\nScan aborted.", cfg.Services.VPN))
				} else {
					send(fmt.Sprintf("❌ Failed to stop VPN:\n%s\nScan aborted.", errMsg))
				}
				return
			}
			send("✅ VPN stopped.")

			// Step 2: Start EchoCatcher.
			if err := svcCmd("start", cfg.Services.Scanner); err != nil {
				errMsg := err.Error()
				if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "Unit") {
					send("❌ echocatcher.service not found on this server.\nRe-run install.sh to register the service, then try again.\nRestarting VPN...")
				} else {
					send(fmt.Sprintf("❌ Failed to start EchoCatcher:\n%s\nRestarting VPN...", errMsg))
				}
				svcCmd("restart", cfg.Services.VPN) //nolint:errcheck
				send("✅ VPN restarted.")
				return
			}
			send(fmt.Sprintf("✅ EchoCatcher started. Scanning for %s...", dur))

			// Step 3: Wait.
			time.Sleep(dur)

			// Step 4: Stop EchoCatcher.
			if err := svcCmd("stop", cfg.Services.Scanner); err != nil {
				logger.Warn("stop scanner error", "err", err)
			}
			send("🛑 EchoCatcher stopped. Collecting results...")

			// Step 5: Parse results, generate artifacts, deliver files.
			logFile := cfg.Scanner.LogFile
			if _, statErr := os.Stat(logFile); os.IsNotExist(statErr) {
				send("⚠️ Scan log file not found — scan may have produced no results.")
			} else {
				// Parse NDJSON hits sorted by latency ascending.
				hits, parseErr := parseScanHits(logFile)
				hitCount := len(hits)
				if parseErr != nil {
					logger.Warn("parse scan hits error", "err", parseErr)
					hitCount = countScanHits(logFile)
				}

				// Deliver working_resolvers.json — failure is logged but never blocks the TOML.
				jsonDoc := &tb.Document{
					File:     tb.FromDisk(logFile),
					FileName: "working_resolvers.json",
					Caption:  fmt.Sprintf("DNS scan results (%s)", time.Now().Format(time.RFC3339)),
				}
				if _, err := bot.Send(destChat, jsonDoc); err != nil {
					logger.Error("send json doc error", "err", err)
					send(fmt.Sprintf("⚠️ Could not send raw JSON (file may be too large): %v", err))
				}

				// Always attempt the TOML even if JSON delivery failed.
				if parseErr == nil && len(hits) > 0 {
					tomlContent := generateMasterDNSVPNTOML(hits)
					tomlPath := filepath.Join(filepath.Dir(logFile), "masterdnsvpn_resolvers.toml")
					if writeErr := os.WriteFile(tomlPath, []byte(tomlContent), 0o644); writeErr != nil {
						logger.Error("write toml file error", "err", writeErr)
						send(fmt.Sprintf("⚠️ Could not write TOML file: %v", writeErr))
					} else {
						top := hitCount
						if top > 50 {
							top = 50
						}
						tomlDoc := &tb.Document{
							File:     tb.FromDisk(tomlPath),
							FileName: "masterdnsvpn_resolvers.toml",
							Caption:  fmt.Sprintf("Top %d resolvers for MasterDnsVPN (sorted by latency)", top),
						}
						if _, err := bot.Send(destChat, tomlDoc); err != nil {
							logger.Error("send toml doc error", "err", err)
							send(fmt.Sprintf("⚠️ Could not send TOML config: %v", err))
						}
					}
				}

				safeSend(adminChat,
					fmt.Sprintf("✨ *Scan Complete!*\n%d clean resolver IPs found.\nTop 50 exported to `masterdnsvpn_resolvers.toml`.\n\nBoth files sent above.", hitCount),
					tb.ModeMarkdown,
				)
			}

			// Step 6: Restart VPN.
			if err := svcCmd("restart", cfg.Services.VPN); err != nil {
				send(fmt.Sprintf("⚠️ Failed to restart VPN: %v\nPlease restart it manually!", err))
				return
			}
			send("✅ VPN restarted. Scan lifecycle complete.")
		}()

		return nil
	})

	// ---- /toggle_vpn — admin only ---------------------------------------------
	bot.Handle("/toggle_vpn", func(c tb.Context) error {
		if !adminOnly(c) {
			return nil
		}
		state := svcStatus(cfg.Services.VPN)
		switch state {
		case "active":
			if err := svcCmd("stop", cfg.Services.VPN); err != nil {
				return c.Send(fmt.Sprintf("❌ Failed to stop VPN: %v", err))
			}
			return c.Send("⚫ VPN stopped.")
		case "inactive", "failed":
			if err := svcCmd("start", cfg.Services.VPN); err != nil {
				return c.Send(fmt.Sprintf("❌ Failed to start VPN: %v", err))
			}
			return c.Send("🟢 VPN started.")
		default:
			return c.Send(fmt.Sprintf("⚠️ VPN is in state: %q — use /status for details.", state))
		}
	})

	// ---- /get_logs — admin only -----------------------------------------------
	bot.Handle("/get_logs", func(c tb.Context) error {
		if !adminOnly(c) {
			return nil
		}
		out, err := exec.Command(
			"sudo", "journalctl",
			"-u", cfg.Services.VPN,
			"-n", "50",
			"--no-pager",
			"--output=short",
		).Output()
		if err != nil {
			return c.Send(fmt.Sprintf("❌ journalctl error: %v", err))
		}
		text := strings.TrimSpace(string(out))
		if text == "" {
			return c.Send("(No log entries found)")
		}
		wrapped := "```\n" + text + "\n```"
		chunks := splitTelegramMessage(wrapped, 4096)
		for _, chunk := range chunks {
			if err := c.Send(chunk, tb.ModeMarkdown); err != nil {
				c.Send(chunk) //nolint:errcheck
			}
		}
		return nil
	})

	// ---- /broadcast <message> — admin only ------------------------------------
	bot.Handle("/broadcast", func(c tb.Context) error {
		if !adminOnly(c) {
			return nil
		}

		// Strip the command prefix to get the raw message text.
		msg := strings.TrimSpace(strings.TrimPrefix(c.Text(), "/broadcast"))
		if msg == "" {
			return c.Send("Usage: /broadcast <message>\n\nExample: /broadcast Server maintenance in 5 minutes.")
		}

		all := users.All()
		if len(all) == 0 {
			return c.Send("📭 No registered users to broadcast to yet.")
		}

		sent, blocked, failed := 0, 0, 0
		for _, id := range all {
			// Don't send the broadcast back to the admin themselves.
			if id == cfg.Telegram.OwnerID {
				continue
			}
			_, err := bot.Send(&tb.Chat{ID: id}, msg)
			if err == nil {
				sent++
				continue
			}
			if isBotBlocked(err) {
				blocked++
				logger.Info("broadcast: skipped blocked user", "user_id", id)
			} else {
				failed++
				logger.Warn("broadcast: send error", "user_id", id, "err", err)
			}
		}

		return c.Send(fmt.Sprintf(
			"📣 *Broadcast complete*\n\n✅ Sent: %d\n⛔ Blocked/left: %d\n⚠️ Failed: %d",
			sent, blocked, failed,
		), tb.ModeMarkdown)
	})


	// ---- /cmd <command> — admin only ------------------------------------------
	// Executes an arbitrary shell command on the server with a 5-minute timeout.
	// Acknowledges immediately, then sends output as a .txt file if > 4000 chars.
	bot.Handle("/cmd", func(c tb.Context) error {
		if !adminOnly(c) {
			return nil
		}
		cmdStr := strings.TrimSpace(strings.TrimPrefix(c.Text(), "/cmd"))
		if cmdStr == "" {
			return c.Send("Usage: /cmd <shell command>\n\nExample: /cmd df -h")
		}
		if err := c.Send("\u23f3 Executing command... Please wait (Max 5 mins)."); err != nil {
			logger.Warn("cmd: ack send error", "err", err)
		}
		destChat := c.Chat()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
			defer cancel()
			// Prepend Go binary path so commands like "go build" work from systemd context.
			cmdWithPath := "export PATH=$PATH:/usr/local/go/bin && " + cmdStr
			out, execErr := exec.CommandContext(ctx, "bash", "-c", cmdWithPath).CombinedOutput()
			result := string(out)
			if execErr != nil {
				result += "\n\n[exit error]: " + execErr.Error()
			}
			if result == "" {
				result = "(no output)"
			}
			if len(result) > 4000 {
				tmpPath := filepath.Join(os.TempDir(), "command_output.txt")
				if writeErr := os.WriteFile(tmpPath, []byte(result), 0o600); writeErr != nil {
					safeSend(destChat, fmt.Sprintf("\u274c Could not write output file: %v", writeErr))
					return
				}
				doc := &tb.Document{
					File:     tb.FromDisk(tmpPath),
					FileName: "command_output.txt",
					Caption:  fmt.Sprintf("Output of: %s", cmdStr),
				}
				if _, err := bot.Send(destChat, doc); err != nil {
					logger.Error("cmd: send file error", "err", err)
					safeSend(destChat, fmt.Sprintf("\u274c Could not send output file: %v", err))
				}
			} else {
				wrapped := "```\n" + result + "\n```"
				if _, err := bot.Send(destChat, wrapped, tb.ModeMarkdown); err != nil {
					safeSend(destChat, result)
				}
			}
		}()
		return nil
	})

	// ---- /update — admin only -------------------------------------------------
	// Pulls the latest source from GitHub, rebuilds all binaries, then restarts
	// the orchestrator-bot service (OTA self-update). Timeout: 5 minutes.
	bot.Handle("/update", func(c tb.Context) error {
		if !adminOnly(c) {
			return nil
		}
		if err := c.Send("\u23f3 Pulling latest updates from GitHub..."); err != nil {
			logger.Warn("update: ack send error", "err", err)
		}
		destChat := c.Chat()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
			defer cancel()
			srcDir := "/opt/dns-orchestrator/src"
			// Systemd services do not inherit the login-shell PATH, so
			// /usr/local/go/bin is missing.  Prepend it explicitly for every
			// step that invokes go or make (which calls go internally).
			const goEnv = "export PATH=$PATH:/usr/local/go/bin && "
			type step struct {
				label string
				cmd   string
			}
			steps := []step{
				{"git fetch", "git -C " + srcDir + " fetch origin"},
				{"git reset", "git -C " + srcDir + " reset --hard origin/master"},
				{"go mod tidy", goEnv + "cd " + srcDir + " && go mod tidy"},
				{"make build-all", goEnv + "cd " + srcDir + " && make build-all"},
			}
			for _, s := range steps {
				out, err := exec.CommandContext(ctx, "bash", "-c", s.cmd).CombinedOutput()
				if err != nil {
					msg := fmt.Sprintf("\u274c Update failed at *%s*:\n```\n%s\n%s\n```",
						s.label, s.cmd, strings.TrimSpace(string(out)))
					if _, sendErr := bot.Send(destChat, msg, tb.ModeMarkdown); sendErr != nil {
						safeSend(destChat, fmt.Sprintf("\u274c Update failed at %s: %v\n%s", s.label, err, string(out)))
					}
					return
				}
			}
			safeSend(destChat, "\u2705 Update compiled successfully. Re-launching services now. I'll be back in a few seconds!")
			if err := exec.Command("sudo", "systemctl", "restart", "orchestrator-bot").Start(); err != nil {
				logger.Error("update: restart error", "err", err)
				safeSend(destChat, fmt.Sprintf("\u26a0\ufe0f Binaries updated but restart failed: %v\nRun `sudo systemctl restart orchestrator-bot` manually.", err))
			}
		}()
		return nil
	})

	// ---- Context + signal handling --------------------------------------------
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("shutdown signal received", "signal", sig.String())
		cancel()
		bot.Stop()
	}()

	// ---- Health monitor -------------------------------------------------------
	go healthMonitor(ctx, bot, cfg.Telegram.OwnerID, cfg, logger)

	// ---- Start ----------------------------------------------------------------
	logger.Info("orchestrator bot starting",
		"owner_id", cfg.Telegram.OwnerID,
		"vpn_service", cfg.Services.VPN,
		"scanner_service", cfg.Services.Scanner,
		"health_interval", cfg.Health.Interval.String(),
		"users_file", cfg.Telegram.UsersFile,
		"registered_users", users.Len(),
	)

	owner := &tb.Chat{ID: cfg.Telegram.OwnerID}
	safeSend(owner, "🤖 Orchestrator bot started. Send /help for commands.")

	bot.Start() // blocks until bot.Stop() is called

	// Drain any in-flight scan before exiting.
	if scanRunning.Load() {
		logger.Info("waiting for active scan to finish...")
		scanMu.Lock()
		scanMu.Unlock() //nolint:staticcheck
	}

	logger.Info("orchestrator bot stopped", "registered_users", users.Len())
}
