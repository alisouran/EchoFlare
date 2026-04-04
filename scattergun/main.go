// scattergun: stateless, asynchronous DNS probe sender.
//
// Usage:
//
//	./scattergun -list ips.txt -domain example.com -workers 10 -retries 1 -jitter 150ms
//	./scattergun -list ips.txt -domain example.com -pad 1000
//
// For each IP in the input file, scattergun crafts a DNS query whose QNAME
// encodes the target IP and a Unix timestamp, then fires it over UDP without
// waiting for any reply ("fire-and-forget").  The companion echocatcher binary
// runs on an external authoritative nameserver and logs every query that arrives.
//
// Phase 3 — Payload Sieve:
//
//	-pad <bytes>   Inflates the UDP packet to the specified size using the EDNS0
//	               Padding Option (RFC 7830, Option Code 12).  Use this to simulate
//	               the payload size of a real DNS tunnel (e.g. MasterDnsVPN) and
//	               reveal ISP DPI rules that drop large UDP/53 packets.
//	               Recommended: -pad 1000 (or higher, matching your tunnel MTU).
//
//	-qtype <type>  Query type: "A" (default), "TXT", or "AAAA".
//	               A 1000-byte padded TXT query looks far more legitimate to a
//	               firewall than a 1000-byte padded A query — combine with -pad.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/user/scattergun/internal/payload"
)

// ---------------------------------------------------------------------------
// Global lock-free counters (updated from many goroutines concurrently).
// ---------------------------------------------------------------------------

var (
	sentCount atomic.Int64 // packets successfully written to the socket
	errCount  atomic.Int64 // UDP dial or write errors
	skipCount atomic.Int64 // lines skipped (invalid IP, pack error, etc.)
)

// ---------------------------------------------------------------------------
// CLI configuration
// ---------------------------------------------------------------------------

type config struct {
	listFile string
	domain   string
	workers  int
	retries  int
	jitter   time.Duration
	pad      int    // target wire-size in bytes for EDNS0 padding (0 = disabled)
	qtype    string // query type: "A", "TXT", or "AAAA"
	debug    bool   // print a line to stdout for every packet sent
	canary   string // if set, send one packet directly to this VPS IP and exit
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.listFile, "list", "", "Path to newline-separated list of resolver IPs (required)")
	flag.StringVar(&cfg.domain, "domain", "", "Root scan domain, e.g. scan.yourdomain.com (required)")
	flag.IntVar(&cfg.workers, "workers", 10, "Number of concurrent sender goroutines")
	flag.IntVar(&cfg.retries, "retries", 1, "Number of UDP sends per IP (to mitigate packet loss)")
	flag.DurationVar(&cfg.jitter, "jitter", 150*time.Millisecond, "Max random sleep between retries")
	flag.IntVar(&cfg.pad, "pad", 0, "Inflate DNS packet to this many bytes using EDNS0 Padding (RFC 7830). 0 = disabled. Use -pad 1000 to simulate VPN tunnel traffic.")
	flag.StringVar(&cfg.qtype, "qtype", "TXT", `DNS query type: "TXT" (default), "A", or "AAAA". Combine with -pad for realistic DPI simulation.`)
	flag.BoolVar(&cfg.debug, "debug", false, "Print a [DEBUG] line to stdout for every packet sent (proof-of-life)")
	flag.StringVar(&cfg.canary, "canary", "", "VPS IP to send a single test packet to directly (bypasses -list). Prints [CANARY] status and exits.")
	flag.Parse()

	ok := true
	if cfg.listFile == "" && cfg.canary == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -list is required (or use -canary <vps-ip> for a single test packet)")
		ok = false
	}
	if cfg.domain == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -domain is required")
		ok = false
	}
	if cfg.workers < 1 {
		fmt.Fprintln(os.Stderr, "ERROR: -workers must be >= 1")
		ok = false
	}
	if cfg.retries < 1 {
		fmt.Fprintln(os.Stderr, "ERROR: -retries must be >= 1")
		ok = false
	}
	if cfg.pad < 0 {
		fmt.Fprintln(os.Stderr, "ERROR: -pad must be >= 0")
		ok = false
	}
	switch strings.ToUpper(cfg.qtype) {
	case "A", "TXT", "AAAA":
		cfg.qtype = strings.ToUpper(cfg.qtype)
	default:
		fmt.Fprintf(os.Stderr, "ERROR: -qtype %q is not supported; choose A, TXT, or AAAA\n", cfg.qtype)
		ok = false
	}
	if !ok {
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

	qtype := qtypeToUint16(cfg.qtype)

	if cfg.pad > 0 {
		log.Printf("INFO payload sieve active: targeting %d-byte packets, qtype=%s", cfg.pad, cfg.qtype)
	}

	// ---- Canary mode: send one packet directly to the VPS and exit -----------
	// Use -canary <vps-ip> to verify the VPS firewall and EchoCatcher are working
	// before running a full scan.  EchoCatcher will log target_ip=127.0.0.1 (canary
	// marker) and forwarder_ip=<your-machine-ip>, confirming the path is open.
	if cfg.canary != "" {
		qname, err := payload.BuildQNAME("127.0.0.1", cfg.domain)
		if err != nil {
			log.Fatalf("[CANARY] Could not build QNAME: %v", err)
		}
		msgBytes, err := buildMsg(qname, qtype, cfg.pad)
		if err != nil {
			log.Fatalf("[CANARY] Could not pack DNS message: %v", err)
		}
		fmt.Printf("[CANARY] Sending test packet to %s:53\n", cfg.canary)
		fmt.Printf("[CANARY] QNAME: %s\n", qname)
		fmt.Printf("[CANARY] Packet size: %d bytes\n", len(msgBytes))
		if err := sendUDP(cfg.canary, msgBytes); err != nil {
			fmt.Fprintf(os.Stderr, "[CANARY] FAILED to send: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[CANARY] Packet sent! Watch echocatcher stdout for [INGRESS] and dns_hit with target_ip=127.0.0.1")
		os.Exit(0)
	}

	// ---- Open IP list ---------------------------------------------------------
	f, err := os.Open(cfg.listFile)
	if err != nil {
		log.Fatalf("ERROR cannot open IP list %q: %v", cfg.listFile, err)
	}
	defer f.Close()

	// ---- Context + signal handling --------------------------------------------
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("INFO received signal %s, draining workers and shutting down...", sig)
		cancel()
	}()

	// ---- Launch worker pool ---------------------------------------------------
	// Buffer is workers*2 so the feeder goroutine can stay a little ahead
	// without blocking, absorbing small bursts of file I/O latency.
	ipChan := make(chan string, cfg.workers*2)
	var wg sync.WaitGroup
	for i := 0; i < cfg.workers; i++ {
		wg.Add(1)
		go worker(ctx, ipChan, cfg.domain, cfg.retries, cfg.jitter, qtype, cfg.pad, cfg.debug, &wg)
	}

	// ---- Progress ticker ------------------------------------------------------
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Printf("[progress] sent=%d errors=%d skipped=%d\n",
					sentCount.Load(), errCount.Load(), skipCount.Load())
			case <-ctx.Done():
				return
			}
		}
	}()

	// ---- Feeder goroutine -----------------------------------------------------
	// Runs concurrently so that wg.Wait() below is reachable immediately,
	// keeping the main goroutine responsive to the context cancellation.
	go func() {
		scanner := bufio.NewScanner(f)
		lineCount := 0
	feedLoop:
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue // skip blanks and comments
			}
			lineCount++
			select {
			case ipChan <- line:
			case <-ctx.Done():
				// Shutdown was requested — stop feeding new IPs.
				break feedLoop
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("ERROR reading IP list: %v", err)
		}
		if lineCount == 0 {
			log.Println("WARN IP list contained no valid entries")
		}
		close(ipChan) // signals workers that there is no more input
	}()

	// ---- Wait for completion --------------------------------------------------
	wg.Wait()
	fmt.Printf("[done] sent=%d errors=%d skipped=%d\n",
		sentCount.Load(), errCount.Load(), skipCount.Load())
}
