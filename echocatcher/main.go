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
	"encoding/binary"
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
		// Estimate the wire size by re-packing the message.  We use Pack()
		// rather than Len() because Len() can panic on truncated/malformed
		// messages; if Pack() fails we fall back to 0 rather than crashing.
		var payloadBytes int
		if packed, err := r.Pack(); err == nil {
			payloadBytes = len(packed)
		}

		// Identify the resolver that forwarded the query to us.
		forwarderAddr := w.RemoteAddr().String()
		forwarderIP, _, err := net.SplitHostPort(forwarderAddr)
		if err != nil {
			// Fallback: use the raw string (should not normally happen).
			forwarderIP = forwarderAddr
		}

		// Emit a human-readable [INGRESS] line for every incoming packet so
		// it's immediately visible in a live terminal without parsing JSON.
		// This fires before domain matching, proving packets reach the process.
		qnames := make([]string, 0, len(r.Question))
		for _, q := range r.Question {
			qnames = append(qnames, q.Name)
		}
		fmt.Printf("[INGRESS] from %s | %s (%d bytes)\n",
			forwarderIP, strings.Join(qnames, ", "), payloadBytes)

		// Prepare the reply message.  SetReply copies the question section,
		// sets QR=1, and defaults RCODE to NOERROR.
		m := new(dns.Msg)
		m.SetReply(r)
		// Authoritative=true prevents resolvers from re-querying other
		// nameservers and from treating the answer as non-authoritative.
		m.Authoritative = true

		for _, q := range r.Question {
			qname := strings.ToLower(q.Name) // DNS names are case-insensitive

			// Log every query we receive — even non-matching ones — so we can
			// confirm packets are reaching the process regardless of domain match.
			if !strings.HasSuffix(qname, strings.ToLower(suffix)) {
				logger.Info("dns_raw_packet",
					"name", q.Name,
					"forwarder", forwarderIP,
					"payload_bytes", payloadBytes,
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

			encodedIP := parts[0]
			tsStr := parts[1]

			// ---- Decode target IP from base36 --------------------------------
			targetIP := decodeBase36IP(encodedIP, logger)

			// ---- Decode timestamp and compute latency ------------------------
			var latencySec int64
			// scattergun encodes the timestamp in base36 (e.g. "lncy2g").
			ts, err := strconv.ParseInt(tsStr, 36, 64)
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

// decodeBase36IP converts a base36-encoded IP string back to dotted/colon notation.
// IPv4 is a single base36 uint32 label (e.g. "1d1b2h").
// IPv6 is two base36 uint64 halves joined by "-" (e.g. "3abc...-...4def...").
// Returns "<decode-error>" on failure and logs a warning.
func decodeBase36IP(encoded string, logger *slog.Logger) string {
	if strings.Contains(encoded, "-") {
		// IPv6 — two base36 uint64 halves separated by "-"
		halves := strings.SplitN(encoded, "-", 2)
		hi, err1 := strconv.ParseUint(halves[0], 36, 64)
		lo, err2 := strconv.ParseUint(halves[1], 36, 64)
		if err1 != nil || err2 != nil {
			logger.Warn("base36 ipv6 decode error", "encoded", encoded)
			return "<decode-error>"
		}
		b := make([]byte, 16)
		binary.BigEndian.PutUint64(b[:8], hi)
		binary.BigEndian.PutUint64(b[8:], lo)
		return net.IP(b).String()
	}
	// IPv4 — single base36 uint32
	ipInt, err := strconv.ParseUint(encoded, 36, 32)
	if err != nil {
		logger.Warn("base36 ipv4 decode error", "encoded", encoded, "err", err)
		return "<decode-error>"
	}
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(ipInt))
	return net.IP(b).String()
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
	// Use a catch-all "." handler so every UDP/53 packet is logged, even if the
	// query doesn't match our domain.  This makes it easy to confirm packets are
	// reaching the process at all.  makeHandler still filters by domain suffix for
	// structured dns_hit logging; unmatched queries log as dns_raw_packet.
	dns.HandleFunc(".", makeHandler(cfg.domain, logger, &queryCount))

	// ---- Start DNS servers (UDP + TCP in parallel) ----------------------------
	// Modern recursive resolvers retry over TCP when a UDP response is truncated
	// or when they prefer reliability.  Running both transports is required to
	// catch all successful recursive queries.
	udpServer := &dns.Server{
		Addr:    cfg.bind,
		Net:     "udp",
		Handler: dns.DefaultServeMux,
	}
	tcpServer := &dns.Server{
		Addr:    cfg.bind,
		Net:     "tcp",
		Handler: dns.DefaultServeMux,
	}

	serverErr := make(chan error, 2)

	startServer := func(srv *dns.Server) {
		logger.Info("echocatcher starting",
			"bind", srv.Addr,
			"net", srv.Net,
			"domain", cfg.domain,
			"log", cfg.logFile,
		)
		if err := srv.ListenAndServe(); err != nil {
			serverErr <- fmt.Errorf("%s: %w", srv.Net, err)
		}
	}

	go startServer(udpServer)
	go startServer(tcpServer)

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

	// ---- Graceful shutdown (both transports) ----------------------------------
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()

	for _, srv := range []*dns.Server{udpServer, tcpServer} {
		if err := srv.ShutdownContext(shutCtx); err != nil {
			logger.Error("shutdown error", "net", srv.Net, "err", err)
		}
	}

	logger.Info("echocatcher stopped",
		"total_queries_logged", queryCount.Load(),
	)
}
