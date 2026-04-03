// scattergun: stateless, asynchronous DNS probe sender.
//
// Usage:
//
//	./scattergun -list ips.txt -domain scan.example.com -workers 10 -retries 1 -jitter 150ms
//	./scattergun -list ips.txt -domain scan.example.com -pad 1000 -qtype TXT
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
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
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
	flag.StringVar(&cfg.qtype, "qtype", "A", `DNS query type: "A" (default), "TXT", or "AAAA". Combine with -pad for realistic DPI simulation.`)
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

// qtypeToUint16 maps the string flag value to the miekg/dns constant.
func qtypeToUint16(qtype string) uint16 {
	switch qtype {
	case "TXT":
		return dns.TypeTXT
	case "AAAA":
		return dns.TypeAAAA
	default:
		return dns.TypeA
	}
}

// ---------------------------------------------------------------------------
// QNAME construction
// ---------------------------------------------------------------------------

// buildQNAME returns the fully-qualified DNS name to query for a given raw IP
// string.  The format encodes the target IP and a Unix timestamp in Base36 so
// that the resulting labels look like random CDN node identifiers rather than
// the fixed-length all-hex pattern that DPI systems flag as DNS tunneling.
//
//	<base36_ip>.<base36_ts>.<domain>.
//	e.g.  1d1x2h.lncy2g.scan.yourdomain.com.   (IPv4)
//	      3x1a2b...x...4c5d.lncy2g.scan.yourdomain.com.  (IPv6, hi "x" lo)
func buildQNAME(rawIP, domain string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %q", rawIP)
	}

	var encodedIP string
	if v4 := ip.To4(); v4 != nil {
		// IPv4 → uint32 → base36 (max 7 chars, e.g. "2mowkjv" for 255.255.255.255)
		ipInt := binary.BigEndian.Uint32(v4)
		encodedIP = strconv.FormatUint(uint64(ipInt), 36)
	} else {
		// IPv6 → two uint64 halves in base36, joined by "x" (not a base36 digit)
		b := ip.To16()
		hi := binary.BigEndian.Uint64(b[:8])
		lo := binary.BigEndian.Uint64(b[8:])
		encodedIP = strconv.FormatUint(hi, 36) + "x" + strconv.FormatUint(lo, 36)
	}

	ts := time.Now().Unix()
	// dns.Fqdn appends the trailing dot required by the DNS wire format.
	return dns.Fqdn(fmt.Sprintf("%s.%s.%s", encodedIP, strconv.FormatInt(ts, 36), domain)), nil
}

// ---------------------------------------------------------------------------
// DNS message builder
// ---------------------------------------------------------------------------

// buildMsg packs a DNS query for the given FQDN into wire bytes.
//
//   - qtype controls the query type (TypeA, TypeTXT, TypeAAAA).
//   - padBytes, if > 0, appends an EDNS0 OPT record with an RFC 7830 Padding
//     option (Option Code 12) that inflates the packet to the requested size.
//     This is the Phase 3 "Payload Sieve": a large padded query reveals whether
//     the ISP drops heavy UDP/53 datagrams — as a real DNS tunnel would send.
func buildMsg(qname string, qtype uint16, padBytes int) ([]byte, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = true

	if padBytes > 0 {
		// Pack once without padding to measure the baseline size.
		baseline, err := m.Pack()
		if err != nil {
			return nil, err
		}
		// OPT RR overhead (name=1 + type=2 + class=2 + ttl=4 + rdlen=2) = 11 bytes.
		// EDNS0_PADDING option header (code=2 + len=2) = 4 bytes.
		const optRROverhead = 11
		const padOptHeader = 4
		needed := padBytes - len(baseline) - optRROverhead - padOptHeader
		if needed < 0 {
			needed = 0
		}

		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(dns.DefaultMsgSize)
		pad := new(dns.EDNS0_PADDING)
		pad.Padding = make([]byte, needed)
		opt.Option = append(opt.Option, pad)
		m.Extra = append(m.Extra, opt)
	}

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

	// Randomize the DNS Transaction ID (first 2 bytes of the wire format) for
	// every individual packet so each probe looks unique to DPI inspection.
	if len(msgBytes) >= 2 {
		txid := dns.Id()
		msgBytes[0] = byte(txid >> 8)
		msgBytes[1] = byte(txid)
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
	qtype uint16,
	pad int,
	debug bool,
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

		msgBytes, err := buildMsg(qname, qtype, pad)
		if err != nil {
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
				if debug {
					fmt.Printf("[DEBUG] Sent to %s: %s (Size: %d bytes)\n", rawIP, qname, len(msgBytes))
				}
			}

			// Sleep a random jitter between retries (not after the last one).
			if i < retries-1 && jitter > 0 {
				sleep := time.Duration(rng.Int63n(int64(jitter) + 1))
				time.Sleep(sleep)
			}
		}

		// Mandatory inter-IP delay (50–200 ms) to avoid flooding and ISP rate-limits.
		// This fires regardless of the retries count, keeping probes low-frequency.
		if ctx.Err() == nil {
			interPacketDelay := 50*time.Millisecond + time.Duration(rng.Int63n(int64(150*time.Millisecond)))
			time.Sleep(interPacketDelay)
		}
	}
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
		qname, err := buildQNAME("127.0.0.1", cfg.domain)
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
