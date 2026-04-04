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
	"flag"
	"fmt"
	"os"
	"os/signal"
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

