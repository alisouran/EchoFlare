package main

// service.go — systemd service management and pre-flight helpers.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

func svcCmd(action, service string) error {
	out, err := exec.Command("sudo", "systemctl", action, service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %w — %s", action, service, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// bulldozerCleanup performs the full "clean slate" pre-flight routine:
//
//  1. Stops MasterDnsVPN service (belt-and-suspenders — caller already stops it,
//     but we repeat here in case anything restarted it).
//  2. SIGKILL all dnstt process trees (zombie DNS-tunnel clients that squirt
//     queries for the VPN domain and pollute the capture with false positives).
//  3. Stops + disables systemd-resolved so it can never reclaim port 53.
//  4. Overwrites /etc/resolv.conf with static public DNS so the VPS retains
//     outbound DNS for the Telegram API throughout the scan.
//  5. Force-kills any remaining process on UDP/53 and TCP/53 via fuser.
//
// Every sub-step is logged but never fatal — a partial failure is better than
// aborting the whole scan. echocatcher will either bind or emit a clear error.
func bulldozerCleanup(vpnService string, logger *slog.Logger) {
	// 1. Re-stop the VPN service (idempotent; already stopped by the caller).
	out, err := exec.Command("sudo", "systemctl", "stop", vpnService).CombinedOutput()
	if err != nil {
		logger.Info("bulldozer: systemctl stop vpn (may be harmless)",
			"service", vpnService, "out", strings.TrimSpace(string(out)))
	} else {
		logger.Info("bulldozer: vpn service stopped", "service", vpnService)
	}

	// 2. Kill all dnstt processes by full command-line match (SIGKILL, no mercy).
	out, err = exec.Command("pkill", "-9", "-f", "dnstt").CombinedOutput()
	if err != nil {
		// pkill exits 1 when no matching process was found — not an error.
		logger.Info("bulldozer: pkill dnstt (no match or killed)",
			"out", strings.TrimSpace(string(out)))
	} else {
		logger.Info("bulldozer: killed dnstt processes")
	}

	// 3. Stop + disable systemd-resolved.
	for _, args := range [][]string{
		{"systemctl", "stop", "systemd-resolved"},
		{"systemctl", "disable", "systemd-resolved"},
	} {
		out, err := exec.Command("sudo", args...).CombinedOutput()
		if err != nil {
			logger.Info("bulldozer: systemctl op (may be harmless)",
				"args", strings.Join(args, " "),
				"out", strings.TrimSpace(string(out)))
		} else {
			logger.Info("bulldozer: ok", "args", strings.Join(args, " "))
		}
	}

	// 4. Write static resolv.conf so the VPS keeps outbound DNS for Telegram.
	const staticResolv = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n"
	if err := os.WriteFile("/etc/resolv.conf", []byte(staticResolv), 0o644); err != nil {
		logger.Warn("bulldozer: could not write /etc/resolv.conf", "err", err)
	} else {
		logger.Info("bulldozer: /etc/resolv.conf set to 8.8.8.8/8.8.4.4")
	}

	// 5. Force-kill any process still holding port 53 on either protocol.
	for _, proto := range []string{"udp", "tcp"} {
		portProto := "53/" + proto
		out, err := exec.Command("sudo", "fuser", "-k", portProto).CombinedOutput()
		if err != nil {
			logger.Info("bulldozer: fuser (no owner or killed)",
				"port", portProto, "out", strings.TrimSpace(string(out)))
		} else {
			logger.Info("bulldozer: killed port owner", "port", portProto)
		}
	}
}

// checkDNSPropagation sends a probe query for a synthetic subdomain under the
// scan domain to 8.8.8.8 and checks whether Google's resolver is delegating
// to our authoritative NS correctly.
//
// We query "probe-test.<domain>" via the system dig(1) binary with a strict
// 5-second timeout. Two outcomes count as "propagated":
//   - NXDOMAIN  — our NS replied "no such name", which proves delegation works
//     (the resolver reached echocatcher's NS, got a valid authoritative answer).
//   - NOERROR   — an actual answer arrived (e.g. the A record exists).
//
// Anything else (SERVFAIL, timeout, connection refused) means the NS records
// have not yet reached 8.8.8.8 and the scan should be aborted.
//
// Returns (propagated bool, digOutput string, err error).
func checkDNSPropagation(domain string) (bool, string, error) {
	probe := "probe-test." + domain
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "dig", "@8.8.8.8", probe, "+time=5", "+tries=1").CombinedOutput()
	output := strings.TrimSpace(string(out))

	if ctx.Err() != nil {
		return false, output, fmt.Errorf("dig timed out after 10s")
	}
	if err != nil {
		// dig exits non-zero on network errors but still writes useful output.
		// Fall through to content check below.
		_ = err
	}

	// A response containing NXDOMAIN or NOERROR in the status line means
	// our NS is being reached by 8.8.8.8 — delegation is live.
	if strings.Contains(output, "NXDOMAIN") || strings.Contains(output, "status: NOERROR") {
		return true, output, nil
	}
	return false, output, nil
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

// rewriteEchocatcherService overwrites /etc/systemd/system/echocatcher.service
// with the current domain and log-file path from config, then runs daemon-reload.
// This fixes stale -domain/-log flags baked in by install.sh at install time.
func rewriteEchocatcherService(domain, logFile string) error {
	const unit = "/etc/systemd/system/echocatcher.service"
	content := fmt.Sprintf(`[Unit]
Description=EchoCatcher DNS Receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/echocatcher -domain %s -log %s -bind 0.0.0.0:53
Restart=no
StandardOutput=journal
StandardError=journal
SyslogIdentifier=echocatcher
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, domain, logFile)

	if err := os.WriteFile(unit, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write echocatcher.service: %w", err)
	}
	if out, err := exec.Command("sudo", "systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload: %w — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
