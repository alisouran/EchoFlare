package main

// probe.go — DNS wire-format builder, fire-and-forget UDP sender, worker pool.

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/user/scattergun/internal/payload"
)

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

// buildMsg packs a DNS query for the given FQDN into wire bytes.
//
//   - qtype controls the query type (TypeA, TypeTXT, TypeAAAA).
//   - padBytes, if > 0, appends an EDNS0 OPT record with an RFC 7830 Padding
//     option (Option Code 12) that inflates the packet to the requested size.
//     This is the Phase 3 "Payload Sieve": a large padded query reveals whether
//     the ISP drops heavy UDP/53 datagrams — as a real DNS tunnel would send.
//
// The Transaction ID is set via dns.Id() before packing so each call produces
// a fresh TXID without any post-pack byte mutation (no data race).
func buildMsg(qname string, qtype uint16, padBytes int) ([]byte, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = true
	m.Id = dns.Id() // unique TXID per packet, set cleanly before packing

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
	} else {
		// Baseline EDNS0 OPT record mimicking a modern stub resolver (systemd-resolved,
		// bind9, Chrome).  Three details matter to DPI:
		//   UDPSize=4096   — the value sent by Chrome, Firefox, unbound, systemd-resolved.
		//   EDNS COOKIE    — Option 10 (RFC 7873): 8-byte random client cookie.
		//                    Its presence is the single strongest indicator of a real
		//                    well-behaved stub resolver; bare OPT with RDLEN=0 is a
		//                    known hand-rolled-client fingerprint.
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetUDPSize(4096)

		var cookieBytes [8]byte
		if _, err := crand.Read(cookieBytes[:]); err == nil {
			cookie := &dns.EDNS0_COOKIE{
				Code:   dns.EDNS0COOKIE,
				Cookie: hex.EncodeToString(cookieBytes[:]),
			}
			o.Option = append(o.Option, cookie)
		}

		m.Extra = append(m.Extra, o)
	}

	return m.Pack()
}

// sendUDP dials the target resolver on port 53, sets a write deadline,
// and writes the pre-packed DNS message bytes.  It never reads a reply.
//
// The 500 ms write deadline prevents hanging when the OS send buffer is full
// under high concurrency without being so tight that it causes spurious drops.
// It does NOT wait for a DNS response.
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
	if err := conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		return fmt.Errorf("set deadline %s: %w", targetIP, err)
	}

	if _, err := conn.Write(msgBytes); err != nil {
		return fmt.Errorf("write to %s: %w", targetIP, err)
	}
	return nil
}

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
	// Each worker gets a uniquely seeded RNG sourced from crypto/rand so that
	// workers started in the same nanosecond don't produce identical jitter
	// sequences and synchronize their burst sends.
	var seedBytes [8]byte
	if _, err := crand.Read(seedBytes[:]); err != nil {
		// Fallback: mix process time with goroutine stack address for uniqueness.
		binary.LittleEndian.PutUint64(seedBytes[:], uint64(time.Now().UnixNano()))
	}
	//nolint:gosec // non-cryptographic jitter is intentional here
	rng := rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(seedBytes[:]))))

	for rawIP := range ipChan {
		rawIP = strings.TrimSpace(rawIP)
		if rawIP == "" {
			continue
		}

		// Build the query name once per IP; the timestamp is fixed at the
		// moment of first construction (intentional: all retries carry the
		// same timestamp so the receiver can deduplicate if desired).
		qname, err := payload.BuildQNAME(rawIP, domain)
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
