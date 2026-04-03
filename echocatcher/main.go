// echocatcher: authoritative DNS server that logs incoming probe queries.
//
// Deploy this on an external VPS that is the authoritative nameserver for
// your scan subdomain (e.g. scan.yourdomain.com).  The companion scattergun
// binary fires DNS queries whose QNAMEs encode the target resolver IP and a
// Unix timestamp.  When a remote resolver forwards such a query here,
// echocatcher decodes the original target IP, computes delivery latency, and
// logs a structured JSON record.
//
// Phase 3 — Payload Sieve:
//
//	Each log record now includes "payload_bytes": the raw wire size of the
//	incoming UDP DNS message.  When scattergun is run with -pad 1000, a
//	successful hit with payload_bytes ≥ 1000 proves the resolver can route
//	large UDP/53 packets through the ISP's DPI layer — exactly the condition
//	required for a real DNS tunnel (e.g. MasterDnsVPN) to function.
//
// Usage:
//
//	./echocatcher -domain scan.example.com -log results.json -bind 0.0.0.0:53
//
// Requirements:
//
//	The process needs permission to bind port 53 (run as root, or grant
//	cap_net_bind_service: `setcap cap_net_bind_service=+ep ./echocatcher`)
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// CLI configuration
// ---------------------------------------------------------------------------

type config struct {
	domain  string
	logFile string
	bind    string
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.domain, "domain", "", "Authoritative scan domain, e.g. scan.yourdomain.com (required)")
	flag.StringVar(&cfg.logFile, "log", "echocatcher.log", "Path to JSON log file (appended)")
	flag.StringVar(&cfg.bind, "bind", "0.0.0.0:53", "UDP address to listen on")
	flag.Parse()

	if cfg.domain == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -domain is required")
		flag.Usage()
		os.Exit(1)
	}
	return cfg
}

// ---------------------------------------------------------------------------
// Logger setup
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// DNS handler factory
// ---------------------------------------------------------------------------

// makeHandler returns a dns.HandlerFunc that:
//  1. Extracts the forwarder IP (the resolver that forwarded the probe query).
//  2. Parses the QNAME to recover the original target IP and probe timestamp.
//  3. Records the total wire size of the incoming UDP packet (payload_bytes).
//  4. Logs a structured JSON record via slog.
//  5. Always replies with a dummy A record (1.2.3.4, TTL 60) so the resolver
//     caches the answer and does not re-query, keeping the network quiet.
func makeHandler(domain string, logger *slog.Logger, queryCount *atomic.Int64) dns.HandlerFunc {
	// Build the expected suffix once.  Both the leading dot and the trailing
	// dot from dns.Fqdn are included so we can do a simple HasSuffix check.
	// Example: domain="scan.yourdomain.com" → suffix=".scan.yourdomain.com."
	suffix := "." + dns.Fqdn(domain)

	return func(w dns.ResponseWriter, r *dns.Msg) {
		// Phase 3: capture the total wire size of the incoming DNS message.
		// r.Len() returns the packed byte count of the message as received,
		// including any EDNS0 OPT records (and padding) added by scattergun.
		payloadBytes := r.Len()

		// Identify the resolver that forwarded the query to us.
		forwarderAddr := w.RemoteAddr().String()
		forwarderIP, _, err := net.SplitHostPort(forwarderAddr)
		if err != nil {
			// Fallback: use the raw string (should not normally happen).
			forwarderIP = forwarderAddr
		}

		// Prepare the reply message.  SetReply copies the question section,
		// sets QR=1, and defaults RCODE to NOERROR.
		m := new(dns.Msg)
		m.SetReply(r)
		// Authoritative=true prevents resolvers from re-querying other
		// nameservers and from treating the answer as non-authoritative.
		m.Authoritative = true

		for _, q := range r.Question {
			qname := strings.ToLower(q.Name) // DNS names are case-insensitive

			// Only process queries that match our scan subdomain.
			if !strings.HasSuffix(qname, strings.ToLower(suffix)) {
				logger.Warn("unexpected query (not our domain)",
					"name", q.Name,
					"forwarder", forwarderIP,
				)
				// Still add the dummy A record so the reply is well-formed.
				m.Answer = append(m.Answer, dummyA(q.Name))
				continue
			}

			// Strip the domain suffix to get "<hexip>.<timestamp>".
			inner := strings.TrimSuffix(qname, strings.ToLower(suffix))
			// inner may still have a trailing dot if it was the zone apex —
			// trim it defensively.
			inner = strings.TrimSuffix(inner, ".")

			parts := strings.Split(inner, ".")
			if len(parts) < 2 {
				logger.Warn("malformed qname (too few labels)",
					"name", q.Name,
					"inner", inner,
					"forwarder", forwarderIP,
				)
				m.Answer = append(m.Answer, dummyA(q.Name))
				continue
			}

			hexIP := parts[0]
			tsStr := parts[1]

			// ---- Decode target IP from hex -----------------------------------
			targetIP := decodeHexIP(hexIP, logger)

			// ---- Decode timestamp and compute latency ------------------------
			var latencySec int64
			ts, err := strconv.ParseInt(tsStr, 10, 64)
			if err != nil {
				logger.Warn("timestamp parse error",
					"ts_raw", tsStr,
					"name", q.Name,
					"err", err,
				)
			} else {
				latencySec = time.Now().Unix() - ts
			}

			// ---- Log the successful resolver hit ----------------------------
			queryCount.Add(1)
			logger.Info("dns_hit",
				"target_ip", targetIP,
				"forwarder_ip", forwarderIP,
				"latency_sec", latencySec,
				"payload_bytes", payloadBytes,
				"query", q.Name,
				"time", time.Now().UTC().Format(time.RFC3339),
			)

			m.Answer = append(m.Answer, dummyA(q.Name))
		}

		if err := w.WriteMsg(m); err != nil {
			logger.Error("write reply error",
				"forwarder", forwarderIP,
				"err", err,
			)
		}
	}
}

// decodeHexIP converts a hex-encoded IP string back to dotted notation.
// Returns "<decode-error>" on failure and logs a warning.
func decodeHexIP(hexIP string, logger *slog.Logger) string {
	rawBytes, err := hex.DecodeString(hexIP)
	if err != nil {
		logger.Warn("hex decode error", "hex", hexIP, "err", err)
		return "<decode-error>"
	}
	switch len(rawBytes) {
	case 4:
		return net.IP(rawBytes).String() // IPv4 dotted notation
	case 16:
		return net.IP(rawBytes).String() // IPv6 colon notation
	default:
		logger.Warn("unexpected decoded length",
			"hex", hexIP,
			"len", len(rawBytes),
		)
		return "<decode-error>"
	}
}

// dummyA returns a minimal A record pointing to 1.2.3.4 with a 60-second TTL.
// Returning a real answer (rather than NOERROR with no records) causes
// resolvers to cache the result and not retry, keeping the network quiet.
func dummyA(qname string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP("1.2.3.4").To4(),
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	cfg := parseFlags()

	// ---- Logger ---------------------------------------------------------------
	logger, logFile, err := newLogger(cfg.logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	// ---- Query counter --------------------------------------------------------
	var queryCount atomic.Int64

	// ---- Register DNS handler -------------------------------------------------
	// miekg/dns uses dns.DefaultServeMux (similar to net/http).
	// Register the handler for the scan domain plus a trailing dot (FQDN).
	handlerDomain := dns.Fqdn(cfg.domain)
	dns.HandleFunc(handlerDomain, makeHandler(cfg.domain, logger, &queryCount))

	// ---- Start DNS server -----------------------------------------------------
	server := &dns.Server{
		Addr:    cfg.bind,
		Net:     "udp",
		Handler: dns.DefaultServeMux,
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("echocatcher starting",
			"bind", cfg.bind,
			"domain", cfg.domain,
			"log", cfg.logFile,
		)
		if err := server.ListenAndServe(); err != nil {
			serverErr <- err
		}
	}()

	// ---- Block until signal or server error -----------------------------------
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-serverErr:
		// Common cause: port 53 already in use (EADDRINUSE).
		logger.Error("server error — check that port 53 is available and you have permission to bind it",
			"err", err,
		)
		os.Exit(1)
	}

	// ---- Graceful shutdown ----------------------------------------------------
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()

	if err := server.ShutdownContext(shutCtx); err != nil {
		logger.Error("shutdown error", "err", err)
	}

	logger.Info("echocatcher stopped",
		"total_queries_logged", queryCount.Load(),
	)
}
