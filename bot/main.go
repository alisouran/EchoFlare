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
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	tb "gopkg.in/telebot.v3"
)

// Injected at build time via -ldflags.
var (
	AppVersion = "dev"
	BuildTime  = "unknown"
)

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
	scanDomain := cfg.Scanner.Domain
	if scanDomain == "" {
		// Fallback: grep the config file directly in case the YAML key
		// was written in a format the struct didn't previously capture.
		if data, err := os.ReadFile(cfgPath); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "domain:") {
					v := strings.TrimSpace(strings.TrimPrefix(line, "domain:"))
					v = strings.Trim(v, `"'`)
					if v != "" {
						scanDomain = v
						break
					}
				}
			}
		}
	}
	if scanDomain == "" {
		scanDomain = "NOT SET — add domain: under scanner: in config.yaml"
	}
	adminHelpText := strings.Join([]string{
		"*🤖 EchoFlare Orchestrator*",
		"🏷 Version: `" + AppVersion + "`",
		"🕒 Build: `" + BuildTime + "`",
		"━━━━━━━━━━━━━━━━━━━━━━━━",
		"",
		"*Admin Commands:*",
		"/status — full service states + CPU/RAM",
		"/scan <duration> — run DNS scan (e.g. `/scan 5m`)",
		"  Stops VPN → starts EchoCatcher → waits → sends results → restarts VPN",
		"  Delivers: `working_resolvers.json` + `masterdnsvpn_resolvers.toml` (top 50)",
		"/setdomain <domain> — update scanner domain in config and restart services",
		"/toggle\\_vpn — start or stop the VPN",
		"/get\\_logs — last 50 lines of VPN journal logs",
		"/broadcast <message> — send a message to all registered users",
		"/update — pull latest code from GitHub and rebuild all binaries",
		"/cmd <command> — run a shell command on the server (5-min timeout)",
		"/help — show this message",
		"",
		"*📡 Scan Configuration*",
		"Domain: `" + scanDomain + "`",
		"",
		"Run on your restricted device:",
		"`./scattergun -list resolvers.txt -domain " + scanDomain + "`",
		"With DPI payload test:",
		"`./scattergun -list resolvers.txt -domain " + scanDomain + " -pad 1000 -qtype TXT`",
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

	// ---- /setdomain <domain> — admin only -------------------------------------
	bot.Handle("/setdomain", func(c tb.Context) error {
		if !adminOnly(c) {
			return nil
		}
		args := c.Args()
		if len(args) == 0 {
			return c.Send("Usage: /setdomain <domain>  (e.g. /setdomain r.jibijat.ir)")
		}
		newDomain := strings.ToLower(strings.TrimSpace(args[0]))
		if !domainRe.MatchString(newDomain) {
			return c.Send(fmt.Sprintf("❌ Invalid domain format: %q\nExample: /setdomain r.jibijat.ir", newDomain))
		}

		// Update in-memory config immediately — /scan reads cfg.Scanner.Domain.
		cfg.Scanner.Domain = newDomain

		// Persist to config.yaml.
		if err := writeDomainToConfig(cfgPath, newDomain); err != nil {
			reply(c, fmt.Sprintf("⚠️ Domain updated in memory but could not write config.yaml: %v", err))
		} else {
			if sendErr := c.Send(fmt.Sprintf("✅ Domain successfully updated to `%s` and saved to config.yaml.\n\nRestarting echocatcher to apply...", newDomain), tb.ModeMarkdown); sendErr != nil {
				logger.Error("setdomain: reply error", "err", sendErr)
			}
		}

		// Restart echocatcher so it picks up the new domain, then restart the bot.
		// Both happen in a goroutine so the confirmation is delivered first.
		ownerChat := &tb.Chat{ID: cfg.Telegram.OwnerID}
		go func() {
			if err := svcCmd("restart", cfg.Services.Scanner); err != nil {
				safeSend(ownerChat, fmt.Sprintf("⚠️ echocatcher restart failed: %v", err))
			} else {
				safeSend(ownerChat, "✅ echocatcher restarted.")
			}
			if err := exec.Command("sudo", "systemctl", "restart", "orchestrator-bot").Start(); err != nil {
				safeSend(ownerChat, fmt.Sprintf("⚠️ orchestrator-bot restart failed: %v\nRun manually: sudo systemctl restart orchestrator-bot", err))
			}
		}()
		return nil
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

		destChat := c.Chat()
		adminChat := &tb.Chat{ID: cfg.Telegram.OwnerID}

		initMsg, initErr := bot.Send(destChat,
			buildProgressMsg(dur, 0, 0, cfg.Scanner.Domain, "Starting services..."),
			tb.ModeMarkdown,
		)
		if initErr != nil {
			logger.Warn("scan: could not send progress card", "err", initErr)
		}

		go runScan(dur, cfg.Scanner.Domain, cfg.Scanner.LogFile,
			cfg.Services.VPN, cfg.Services.Scanner,
			bot, destChat, adminChat, initMsg, logger, safeSend)
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
			// Prepend Go binary path and required env vars so go/make work from systemd context.
			const sysEnv = "export PATH=$PATH:/usr/local/go/bin && export HOME=/root && export GOPATH=/root/go && export GOMODCACHE=/root/go/pkg/mod && "
			cmdWithPath := sysEnv + cmdStr
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
		go runUpdate(destChat, cfg, cfgPath, bot, logger, safeSend)
		return nil
	})

	// ---- Free-text handler — catches admin replies to domain prompt -----------
	bot.Handle(tb.OnText, func(c tb.Context) error {
		if !isAdmin(c) {
			return nil
		}
		pendingDomainMu.Lock()
		ch, waiting := pendingDomainPrompts[c.Chat().ID]
		if waiting {
			delete(pendingDomainPrompts, c.Chat().ID)
		}
		pendingDomainMu.Unlock()

		if waiting {
			domain := strings.TrimSpace(c.Text())
			if domain == "" {
				safeSend(c.Chat(), "Domain cannot be empty. /update cancelled.")
				return nil
			}
			ch <- domain
			return nil
		}
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
