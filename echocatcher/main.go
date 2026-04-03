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
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
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
					"qtype", dns.TypeToString[q.Qtype],
					"forwarder", forwarderIP,
					"payload_bytes", payloadBytes,
				)
				m.Answer = append(m.Answer, replyRR(q))
				continue
			}

			// Only structured dns_hit logging for TXT queries (the DPI-evading
			// default).  Other qtypes are still logged as dns_raw_packet so
			// canary tests with explicit -qtype A still produce visible output.
			if q.Qtype != dns.TypeTXT {
				logger.Info("dns_raw_packet",
					"name", q.Name,
					"qtype", dns.TypeToString[q.Qtype],
					"forwarder", forwarderIP,
					"payload_bytes", payloadBytes,
					"note", "non-TXT qtype; use -qtype TXT for structured logging",
				)
				m.Answer = append(m.Answer, replyRR(q))
				continue
			}

			// Strip the domain suffix to isolate the 52-char Base32 label.
			inner := strings.TrimSuffix(qname, strings.ToLower(suffix))
			inner = strings.TrimSuffix(inner, ".") // remove any trailing dot

			// The label is the first (and only) component before the domain.
			// Split defensively but we expect exactly one label.
			parts := strings.Split(inner, ".")
			label := parts[0]

			// ---- Decode Base32 payload → target IP + timestamp --------------
			targetIP, ts, err := decodeBase32Payload(label)
			if err != nil {
				logger.Warn("base32 decode error",
					"label", label,
					"name", q.Name,
					"forwarder", forwarderIP,
					"err", err,
				)
				m.Answer = append(m.Answer, replyRR(q))
				continue
			}

			latencySec := time.Now().Unix() - ts

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

			m.Answer = append(m.Answer, replyRR(q))
		}

		if err := w.WriteMsg(m); err != nil {
			logger.Error("write reply error",
				"forwarder", forwarderIP,
				"err", err,
			)
		}
	}
}

// b32dec is the standard RFC 4648 Base32 decoder without padding.
// Matches the encoder used in scattergun's buildQNAME.
var b32dec = base32.StdEncoding.WithPadding(base32.NoPadding)

// decodeBase32Payload decodes a 52-char Base32 label produced by scattergun
// back into the target IP string and Unix timestamp.
//
// Expected payload layout (32 bytes):
//
//	IPv4: [0x04][4-byte IP][8-byte TS big-endian][19 random filler]
//	IPv6: [0x06][16-byte IP][8-byte TS big-endian][7 random filler]
func decodeBase32Payload(label string) (targetIP string, ts int64, err error) {
	payload, err := b32dec.DecodeString(strings.ToUpper(label))
	if err != nil {
		return "", 0, fmt.Errorf("base32 decode: %w", err)
	}
	if len(payload) < 13 {
		return "", 0, fmt.Errorf("payload too short: %d bytes", len(payload))
	}

	switch payload[0] {
	case 0x04:
		if len(payload) < 13 {
			return "", 0, fmt.Errorf("IPv4 payload too short")
		}
		ip := net.IP(payload[1:5])
		ts = int64(binary.BigEndian.Uint64(payload[5:13]))
		return ip.String(), ts, nil
	case 0x06:
		if len(payload) < 25 {
			return "", 0, fmt.Errorf("IPv6 payload too short")
		}
		ip := net.IP(payload[1:17])
		ts = int64(binary.BigEndian.Uint64(payload[17:25]))
		return ip.String(), ts, nil
	default:
		return "", 0, fmt.Errorf("unknown type byte: 0x%02x", payload[0])
	}
}

// replyRR returns a well-formed answer record appropriate for the query type.
// For TXT queries it returns a plausible SPF record (TTL 300) so the reply
// looks like an authoritative SPF/DKIM response and resolvers cache it.
// For all other types it falls back to a dummy A record (1.2.3.4, TTL 60).
func replyRR(q dns.Question) dns.RR {
	if q.Qtype == dns.TypeTXT {
		return &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{"v=spf1 -all"},
		}
	}
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
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
