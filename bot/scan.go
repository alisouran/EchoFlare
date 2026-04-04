package main

// scan.go — scan state, result parsing, and the runScan lifecycle function.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tb "gopkg.in/telebot.v3"
)

// ---------------------------------------------------------------------------
// Scan state (package-level — accessed from main.go handlers and runScan)
// ---------------------------------------------------------------------------

var (
	scanMu      sync.Mutex  // held for the duration of a /scan operation
	scanRunning atomic.Bool // true while a scan is in progress
)

// ---------------------------------------------------------------------------
// Scan result types and helpers
// ---------------------------------------------------------------------------

// Hit represents a single successful resolver record from the echocatcher NDJSON log.
type Hit struct {
	TargetIP   string  `json:"target_ip"`
	LatencySec float64 `json:"latency_sec"`
}

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

// countRawPackets counts lines in the echocatcher log that are dns_raw_packet
// events — packets that arrived on port 53 but didn't match the scan domain.
// A non-zero count with zero dns_hit entries means traffic is reaching the VPS
// but the QNAME prefix isn't matching (wrong domain, DPI stripping, etc.).
func countRawPackets(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.Contains(line, []byte(`"dns_raw_packet"`)) {
			count++
		}
	}
	return count
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

// generateResolversTxt takes the top 100 lowest-latency hits and returns a
// plain-text list of IPs, one per line.
func generateResolversTxt(hits []Hit) string {
	top := hits
	if len(top) > 100 {
		top = top[:100]
	}
	var sb strings.Builder
	for _, h := range top {
		sb.WriteString(h.TargetIP + "\n")
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Progress card helpers
// ---------------------------------------------------------------------------

// formatDuration returns a MM:SS string from a time.Duration.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d", m, s)
}

// buildProgressMsg renders the live scan progress card.
// rawCount is the number of dns_raw_packet events — any UDP/53 traffic that
// reached EchoCatcher but didn't decode as a valid EchoFlare probe.
func buildProgressMsg(remaining time.Duration, hits, rawCount int, domain, status string) string {
	bar := "━━━━━━━━━━━━━━━━━━━━━━━━"
	// Compute a smarter status string if the caller passed the default.
	if status == "" {
		switch {
		case hits > 0:
			status = "Probing stealthily... 🔍"
		case rawCount > 0:
			status = "Traffic detected, but no valid EchoFlare probes yet..."
		default:
			status = "Probing stealthily... 🔍"
		}
	}
	rawLine := ""
	if rawCount > 0 {
		rawLine = fmt.Sprintf("\n📶 Raw UDP/53 Traffic: *%s packets* (port open ✅)", formatInt(rawCount))
	}
	return fmt.Sprintf(
		"📡 *EchoFlare Live Scan* _(Promiscuous Mode)_\n%s\n⏳ Remaining Time: `%s`\n🎯 Successful Hits: *%s IPs*%s\n🔎 Active Domain: `%s`\n%s\nStatus: %s",
		bar,
		formatDuration(remaining),
		formatInt(hits),
		rawLine,
		domain,
		bar,
		status,
	)
}

// ---------------------------------------------------------------------------
// runScan — the /scan lifecycle extracted from the handler goroutine
// ---------------------------------------------------------------------------

// runScan executes the full scan lifecycle and is called as a goroutine from
// the /scan handler.  The handler is responsible for acquiring scanMu and
// setting scanRunning before calling this function.
func runScan(
	dur            time.Duration,
	domain         string,
	logFile        string,
	vpnService     string,
	scannerService string,
	bot            *tb.Bot,
	destChat       tb.Recipient,
	adminChat      tb.Recipient,
	initMsg        *tb.Message,
	logger         *slog.Logger,
	safeSend       func(tb.Recipient, string, ...interface{}),
) {
	defer func() {
		scanRunning.Store(false)
		scanMu.Unlock()
	}()

	send := func(text string) { safeSend(destChat, text) }

	// editProgress updates the live card; silently ignores Telegram rate-limit
	// errors (420) — the next tick will retry automatically.
	// Pass status="" to let buildProgressMsg choose the right text based on counts.
	editProgress := func(remaining time.Duration, status string) {
		if initMsg == nil {
			return
		}
		hits := countScanHits(logFile)
		raw := countRawPackets(logFile)
		text := buildProgressMsg(remaining, hits, raw, domain, status)
		if _, err := bot.Edit(initMsg, text, tb.ModeMarkdown); err != nil {
			logger.Debug("scan progress edit error (likely rate-limit)", "err", err)
		}
	}

	// ── Pre-flight step A: DNS propagation check ───────────────────────
	// Verify that 8.8.8.8 is already delegating to our authoritative NS
	// before we burn scan time. Abort immediately if not propagated.
	editProgress(dur, "🔍 Checking DNS propagation...")
	propagated, digOut, digErr := checkDNSPropagation(domain)
	if digErr != nil {
		send(fmt.Sprintf(
			"⚠️ *Scan Aborted: DNS propagation check failed.*\n\n`dig` error: `%v`\n\nCloudflare NS records for `%s` may not be propagated to global DNS (8.8.8.8) yet. Please wait a few minutes and try again.",
			digErr, domain,
		))
		return
	}
	if !propagated {
		send(fmt.Sprintf(
			"⚠️ *Scan Aborted: Cloudflare NS records for `%s` are not yet propagated to global DNS (8.8.8.8).*\n\nPlease wait a few minutes and try again.\n\n_dig output:_\n```\n%s\n```",
			domain, digOut,
		))
		return
	}
	send(fmt.Sprintf(
		"✅ *Pre-flight passed!* Network is clean and DNS for `%s` is propagated to 8.8.8.8. Starting the scan...",
		domain,
	))

	// ── Pre-flight step B: Bulldozer cleanup ───────────────────────────
	// Stop VPN service, kill dnstt zombies, free port 53, fix resolv.conf.
	editProgress(dur, "🔧 Bulldozer cleanup — silencing conflicting processes...")
	bulldozerCleanup(vpnService, logger)

	// Brief pause so the OS fully releases port 53 before echocatcher binds.
	time.Sleep(2 * time.Second)

	// ── Reset log file so counters start at 0 for this scan ───────────────────────
	// Truncate (not delete) to preserve file ownership/permissions.
	if f, truncErr := os.OpenFile(logFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o640); truncErr != nil {
		logger.Warn("scan: could not truncate log file — counter may show stale data", "err", truncErr)
	} else {
		f.Close()
	}

	// ── Step 1: Refresh echocatcher.service, then start ───────────────
	// Rewrite the unit file so -domain/-log always reflect the live config,
	// not whatever install.sh baked in at install time.
	if err := rewriteEchocatcherService(domain, logFile); err != nil {
		logger.Warn("scan: could not rewrite echocatcher.service (using existing unit)", "err", err)
	}
	if err := svcCmd("start", scannerService); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "Unit") {
			send("❌ echocatcher.service not found on this server.\nRe-run install.sh to register the service, then try again.\nRestarting VPN...")
		} else {
			send(fmt.Sprintf("❌ Failed to start EchoCatcher:\n%s\nRestarting VPN...", errMsg))
		}
		svcCmd("restart", vpnService) //nolint:errcheck
		send("✅ VPN restarted.")
		return
	}

	// ── Step 2: Countdown ticker ───────────────────────────────────────
	deadline := time.Now().Add(dur)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	editProgress(dur, "")
tickLoop:
	for {
		select {
		case now := <-ticker.C:
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break tickLoop
			}
			editProgress(remaining, "")
			_ = now
		case <-time.After(time.Until(deadline)):
			break tickLoop
		}
	}

	// ── Step 3: Stop EchoCatcher ───────────────────────────────────────
	editProgress(0, "Stopping scanner...")
	if err := svcCmd("stop", scannerService); err != nil {
		logger.Warn("stop scanner error", "err", err)
	}

	editProgress(0, "Collecting results...")

	// Step 5: Parse results, generate artifacts, deliver files.
	if _, statErr := os.Stat(logFile); os.IsNotExist(statErr) {
		editProgress(0, "⚠️ No results file found.")
		send("⚠️ Scan log file not found — scan may have produced no results.")
	} else {
		hits, parseErr := parseScanHits(logFile)
		hitCount := len(hits)
		if parseErr != nil {
			logger.Warn("parse scan hits error", "err", parseErr)
			hitCount = countScanHits(logFile)
		}

		// Final edit: mark the card as complete.
		bar := "━━━━━━━━━━━━━━━━━━━━━━━━"
		if initMsg != nil {
			completeText := fmt.Sprintf(
				"✅ *Scan Complete!*\n%s\n⏳ Duration: `%s`\n🎯 Total Hits: *%s IPs*\n🔎 Domain: `%s`\n%s\nStatus: Done — sending files...",
				bar, formatDuration(dur), formatInt(hitCount), domain, bar,
			)
			bot.Edit(initMsg, completeText, tb.ModeMarkdown) //nolint:errcheck
		}

		// Deliver working_resolvers.json — failure never blocks the TOML.
		jsonDoc := &tb.Document{
			File:     tb.FromDisk(logFile),
			FileName: "working_resolvers.json",
			Caption:  fmt.Sprintf("DNS scan results (%s)", time.Now().Format(time.RFC3339)),
		}
		if _, err := bot.Send(destChat, jsonDoc); err != nil {
			logger.Error("send json doc error", "err", err)
			send(fmt.Sprintf("⚠️ Could not send raw JSON (file may be too large): %v", err))
		}

		// Always attempt the TXT even if JSON delivery failed.
		if parseErr == nil && len(hits) > 0 {
			txtContent := generateResolversTxt(hits)
			txtPath := filepath.Join(filepath.Dir(logFile), "top100_resolvers.txt")
			if writeErr := os.WriteFile(txtPath, []byte(txtContent), 0o644); writeErr != nil {
				logger.Error("write resolvers txt error", "err", writeErr)
				send(fmt.Sprintf("⚠️ Could not write resolvers file: %v", writeErr))
			} else {
				top := hitCount
				if top > 100 {
					top = 100
				}
				txtDoc := &tb.Document{
					File:     tb.FromDisk(txtPath),
					FileName: "top100_resolvers.txt",
					Caption:  fmt.Sprintf("Top %d resolvers (sorted by latency)", top),
				}
				if _, err := bot.Send(destChat, txtDoc); err != nil {
					logger.Error("send resolvers txt error", "err", err)
					send(fmt.Sprintf("⚠️ Could not send resolvers file: %v", err))
				}
			}
		}

		safeSend(adminChat,
			fmt.Sprintf("✨ *Scan Complete!*\n%s clean resolver IPs found.\nTop 100 exported to `top100_resolvers.txt`.\n\nBoth files sent above.", formatInt(hitCount)),
			tb.ModeMarkdown,
		)

		if hitCount == 0 {
			send("⚠️ 0 hits recorded. Possible causes:\n• Cloud firewall blocking UDP/53 inbound — check your VPS firewall rules\n• EchoCatcher not binding correctly — check: journalctl -u echocatcher -n 50\n• Scattergun rate still too high — try reducing -workers further\n\nRun a quick test: dig @<your-vps-ip> test.yourdomain.com and watch echocatcher logs.")
		}
	}

	// ── Step 4: Restart VPN — restores the service's own DNS handling ──
	if err := svcCmd("restart", vpnService); err != nil {
		send(fmt.Sprintf("⚠️ Failed to restart VPN: %v\nPlease restart it manually!", err))
		return
	}
	send("✅ VPN restarted. Scan lifecycle complete.")
}
