package main

// handler.go — DNS request handler and reply builder for echocatcher.

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/user/scattergun/internal/payload"
)

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
			targetIP, ts, err := payload.DecodeBase32Payload(label)
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
