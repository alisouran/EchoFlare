// scattergun: stateless, asynchronous DNS probe sender.
//
// Usage:
//
//	./scattergun -list ips.txt -domain scan.example.com -workers 200 -retries 3 -jitter 10ms
//
// For each IP in the input file, scattergun crafts a DNS A-query whose QNAME
// encodes the target IP and a Unix timestamp, then fires it over UDP without
// waiting for any reply ("fire-and-forget").  The companion echocatcher binary
// runs on an external authoritative nameserver and logs every query that arrives.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Global lock-free counters (updated from many goroutines concurrently).
// ---------------------------------------------------------------------------

var (
	sentCount  atomic.Int64 // packets successfully written to the socket
	errCount   atomic.Int64 // UDP dial or write errors
	skipCount  atomic.Int64 // lines skipped (invalid IP, pack error, etc.)
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
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.listFile, "list", "", "Path to newline-separated list of resolver IPs (required)")
	flag.StringVar(&cfg.domain, "domain", "", "Root scan domain, e.g. scan.yourdomain.com (required)")
	flag.IntVar(&cfg.workers, "workers", 200, "Number of concurrent sender goroutines")
	flag.IntVar(&cfg.retries, "retries", 3, "Number of UDP sends per IP (to mitigate packet loss)")
	flag.DurationVar(&cfg.jitter, "jitter", 10*time.Millisecond, "Max random sleep between retries")
	flag.Parse()

	ok := true
	if cfg.listFile == "" {
		fmt.Fprintln(os.Stderr, "ERROR: -list is required")
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
	if !ok {
		flag.Usage()
		os.Exit(1)
	}
	return cfg
}

// ---------------------------------------------------------------------------
// QNAME construction
// ---------------------------------------------------------------------------

// buildQNAME returns the fully-qualified DNS name to query for a given raw IP
// string.  The format encodes the target IP as hex and embeds the current Unix
// timestamp so that latency can be computed on the receiver side.
//
//	<hex_ip>.<unix_ts>.<domain>.
//	e.g.  08080808.1712140000.scan.yourdomain.com.
func buildQNAME(rawIP, domain string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %q", rawIP)
	}

	var hexIP string
	if v4 := ip.To4(); v4 != nil {
		// Standard IPv4 → 8 hex characters (e.g. "08080808")
		hexIP = hex.EncodeToString(v4)
	} else {
		// Pure IPv6 → 32 hex characters
		hexIP = hex.EncodeToString(ip.To16())
	}

	ts := time.Now().Unix()
	// dns.Fqdn appends the trailing dot required by the DNS wire format.
	return dns.Fqdn(fmt.Sprintf("%s.%d.%s", hexIP, ts, domain)), nil
}

// ---------------------------------------------------------------------------
// DNS message builder
// ---------------------------------------------------------------------------

// buildMsg packs a standard recursive A-query for the given FQDN into wire
// bytes.  Using miekg/dns ensures correct header flags, question encoding, and
// ID assignment (randomised by the library).
func buildMsg(qname string) ([]byte, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeA)
	m.RecursionDesired = true
	return m.Pack()
}

// ---------------------------------------------------------------------------
// Fire-and-forget UDP send
// ---------------------------------------------------------------------------

// sendUDP dials the target resolver on port 53, sets a short write deadline,
// and writes the pre-packed DNS message bytes.  It never reads a reply.
//
// A short write deadline (100 ms) is used purely to prevent hanging when the
// OS send buffer is full; it does NOT wait for a DNS response.
func sendUDP(targetIP string, msgBytes []byte) error {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, "53"))
	if err != nil {
		return fmt.Errorf("resolve %s: %w", targetIP, err)
	}
	// DialUDP creates a "connected" UDP socket bound to raddr.  The kernel
	// discards any unexpected inbound datagrams automatically, so there is
	// zero risk of accidentally reading a reply.
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", targetIP, err)
	}
	defer conn.Close()

	// Only a write deadline — no read deadline because we never read.
	if err := conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return fmt.Errorf("set deadline %s: %w", targetIP, err)
	}
	if _, err := conn.Write(msgBytes); err != nil {
		return fmt.Errorf("write to %s: %w", targetIP, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Worker goroutine
// ---------------------------------------------------------------------------

// worker reads IP strings from ipChan and fires DNS probes until the channel
// is closed or the context is cancelled.
func worker(
	ctx context.Context,
	ipChan <-chan string,
	domain string,
	retries int,
	jitter time.Duration,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	// Each worker has its own random source to avoid contention on the global
	// math/rand mutex when hundreds of goroutines run concurrently.
	//nolint:gosec // non-cryptographic jitter is intentional here
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for rawIP := range ipChan {
		rawIP = strings.TrimSpace(rawIP)
		if rawIP == "" {
			continue
		}

		// Build the query name once per IP; the timestamp is fixed at the
		// moment of first construction (intentional: all retries carry the
		// same timestamp so the receiver can deduplicate if desired).
		qname, err := buildQNAME(rawIP, domain)
		if err != nil {
			skipCount.Add(1)
			log.Printf("WARN skip %q: %v", rawIP, err)
			continue
		}

		msgBytes, err := buildMsg(qname)
		if err != nil {
			// Very unlikely with a well-formed QNAME, but handle it.
			skipCount.Add(1)
			log.Printf("WARN pack error for %q (%s): %v", rawIP, qname, err)
			continue
		}

		for i := 0; i < retries; i++ {
			// Respect shutdown signal between retries.
			if ctx.Err() != nil {
				return
			}

			if err := sendUDP(rawIP, msgBytes); err != nil {
				errCount.Add(1)
				log.Printf("DEBUG send error (retry %d/%d) to %s: %v", i+1, retries, rawIP, err)
			} else {
				sentCount.Add(1)
			}

			// Sleep a random jitter between retries (not after the last one).
			if i < retries-1 && jitter > 0 {
				sleep := time.Duration(rng.Int63n(int64(jitter) + 1))
				time.Sleep(sleep)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	cfg := parseFlags()

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
		go worker(ctx, ipChan, cfg.domain, cfg.retries, cfg.jitter, &wg)
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
				break
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
