package main

// health.go — periodic ping-based health monitor that alerts the admin on
// high packet loss.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	tb "gopkg.in/telebot.v3"
)

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
