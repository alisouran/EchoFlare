package main

// update.go — OTA self-update lifecycle and domain-prompt state.

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	tb "gopkg.in/telebot.v3"
)

// domainRe validates domain names for /setdomain and the /update domain prompt.
var domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// pendingDomainPrompts maps a chat ID to a channel that receives the admin's
// reply when the bot is waiting for a missing scan domain during /update.
var (
	pendingDomainMu      sync.Mutex
	pendingDomainPrompts = make(map[int64]chan string)
)

// runUpdate executes the full OTA update lifecycle and is called as a goroutine
// from the /update handler.
func runUpdate(
	destChat *tb.Chat,
	cfg      *Config,
	cfgPath  string,
	bot      *tb.Bot,
	logger   *slog.Logger,
	safeSend func(tb.Recipient, string, ...interface{}),
) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// ── Domain check ────────────────────────────────────────────────
	// If scanner.domain is missing from config.yaml, ask the admin
	// via Telegram before touching the source tree.
	if cfg.Scanner.Domain == "" {
		safeSend(destChat, "⚠️ *scanner.domain* is not set in your config.\n\nPlease reply with your scan domain now (e.g. `scan.yourdomain.com`):", tb.ModeMarkdown)

		replyCh := make(chan string, 1)
		pendingDomainMu.Lock()
		pendingDomainPrompts[destChat.ID] = replyCh
		pendingDomainMu.Unlock()

		var newDomain string
		select {
		case newDomain = <-replyCh:
		case <-time.After(2 * time.Minute):
			safeSend(destChat, "⏱ Timed out waiting for domain. /update cancelled.")
			return
		}

		// Patch the in-memory config and persist to config.yaml.
		cfg.Scanner.Domain = newDomain
		if writeErr := writeDomainToConfig(cfgPath, newDomain); writeErr != nil {
			safeSend(destChat, fmt.Sprintf("⚠️ Domain set in memory but could not write config.yaml: %v", writeErr))
		} else {
			safeSend(destChat, fmt.Sprintf("✅ Domain `%s` saved to config.yaml.", newDomain), tb.ModeMarkdown)
		}
	}

	srcDir := "/opt/dns-orchestrator/src"
	// Systemd services do not inherit the login-shell PATH, so
	// /usr/local/go/bin is missing.  Prepend it explicitly for every
	// step that invokes go or make (which calls go internally).
	const goEnv = "export PATH=$PATH:/usr/local/go/bin && export HOME=/root && export GOPATH=/root/go && export GOMODCACHE=/root/go/pkg/mod && "
	type step struct {
		label string
		cmd   string
	}
	// Build directly to the installed binary paths so the service
	// picks up the new code on restart.  make build-all only writes
	// to bin/ (cross-compiled), never to /usr/local/bin/.
	steps := []step{
		{"git fetch", "git -C " + srcDir + " fetch origin"},
		{"git reset", "git -C " + srcDir + " reset --hard origin/master"},
		{"go mod tidy", goEnv + "cd " + srcDir + " && go mod tidy"},
		{"build bot", goEnv + "cd " + srcDir + " && VERSION=\"rev-$(git rev-parse --short HEAD)\" && BUILD_TIME=\"$(date -u +'%Y-%m-%d %H:%M:%S UTC')\" && go build -trimpath -ldflags=\"-s -w -X 'main.AppVersion=$VERSION' -X 'main.BuildTime=$BUILD_TIME'\" -o /usr/local/bin/orchestrator-bot ./bot/"},
		{"build echocatcher", goEnv + "cd " + srcDir + " && go build -trimpath -ldflags=\"-s -w\" -o /usr/local/bin/echocatcher ./echocatcher/"},
	}
	for _, s := range steps {
		// Notify before each step so the admin sees live progress.
		safeSend(destChat, fmt.Sprintf("\u23f3 Running: *%s*...", s.label), tb.ModeMarkdown)
		out, err := exec.CommandContext(ctx, "bash", "-c", s.cmd).CombinedOutput()
		if err != nil {
			outStr := strings.TrimSpace(string(out))
			if outStr == "" {
				outStr = "(no output)"
			}
			msg := fmt.Sprintf("\u274c Update failed at *%s*:\n```\n%s\n```",
				s.label, outStr)
			if _, sendErr := bot.Send(destChat, msg, tb.ModeMarkdown); sendErr != nil {
				safeSend(destChat, fmt.Sprintf("\u274c Update failed at %s: %v\n%s", s.label, err, outStr))
			}
			return
		}
		safeSend(destChat, fmt.Sprintf("\u2705 *%s* done.", s.label), tb.ModeMarkdown)
	}
	safeSend(destChat, "\u2705 All steps complete. Re-launching services now. I'll be back in a few seconds!")
	if err := exec.Command("sudo", "systemctl", "restart", "orchestrator-bot").Start(); err != nil {
		logger.Error("update: restart error", "err", err)
		safeSend(destChat, fmt.Sprintf("\u26a0\ufe0f Binaries updated but restart failed: %v\nRun `sudo systemctl restart orchestrator-bot` manually.", err))
	}
}
