// Package payload implements the shared Base32 encoding contract between
// scattergun (sender) and echocatcher (receiver).
//
// Both binaries must agree on the exact byte layout of the probe payload.
// Centralising it here makes that contract explicit and testable.
//
// Payload layout (32 bytes → 52-char Base32 label, no "=" padding):
//
//	IPv4: [0x04][4-byte IP][8-byte TS big-endian][19 random filler bytes]
//	IPv6: [0x06][16-byte IP][8-byte TS big-endian][7 random filler bytes]
package payload

import (
	crand "crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Codec is the standard RFC 4648 Base32 alphabet without padding characters.
// Produces uppercase A-Z2-7 output identical to DKIM selector labels, which
// confounds DPI signatures that flag short high-entropy labels as tunneling.
var Codec = base32.StdEncoding.WithPadding(base32.NoPadding)

// payloadBase32Len is the exact Base32-encoded length of the 32-byte probe
// payload (ceil(32*8/5) = 52 chars, NoPadding). Characters beyond this
// position are DKIM camouflage padding and must be stripped before decoding.
const payloadBase32Len = 52

// base32Alphabet is the RFC 4648 Base32 character set used to generate
// random DKIM-style camouflage suffixes.
const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// randBase32Suffix returns n cryptographically random characters from the
// Base32 alphabet, appended to probe labels to mimic DKIM selector queries.
func randBase32Suffix(n int) string {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		return strings.Repeat("A", n) // safe fallback; crypto/rand never fails in practice
	}
	out := make([]byte, n)
	for i, v := range b {
		out[i] = base32Alphabet[int(v)%32]
	}
	return string(out)
}

// BuildQNAME returns the fully-qualified DNS name to query for a given raw IP
// string.  The payload is packed into a fixed 32-byte binary blob and encoded
// as a single Base32 label (52 uppercase chars), mimicking a DKIM/SPF selector
// query (e.g. MFRGGZDFMZTWQ2LKNNWG23TPOBYXE3DPEBXXEZLOOQ.yourdomain.com.).
//
// The filler bytes make every label unique even for the same IP, defeating
// any DPI rule that keys on repeated identical labels.
func BuildQNAME(rawIP, domain string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %q", rawIP)
	}

	payload := make([]byte, 32)
	ts := time.Now().Unix()

	if v4 := ip.To4(); v4 != nil {
		payload[0] = 0x04
		copy(payload[1:5], v4)
		binary.BigEndian.PutUint64(payload[5:13], uint64(ts))
		// bytes 13–31: 19 random filler bytes
		if _, err := crand.Read(payload[13:]); err != nil {
			return "", fmt.Errorf("rand filler: %w", err)
		}
	} else {
		b := ip.To16()
		payload[0] = 0x06
		copy(payload[1:17], b)
		binary.BigEndian.PutUint64(payload[17:25], uint64(ts))
		// bytes 25–31: 7 random filler bytes
		if _, err := crand.Read(payload[25:]); err != nil {
			return "", fmt.Errorf("rand filler: %w", err)
		}
	}

	label := Codec.EncodeToString(payload)      // always 52 chars, uppercase, no "="
	dkim := randBase32Suffix(8)                 // 8-char DKIM camouflage suffix
	// dns.Fqdn appends the trailing dot required by the DNS wire format.
	return dns.Fqdn(fmt.Sprintf("%s%s.%s", label, dkim, domain)), nil
}

// DecodeBase32Payload decodes a 52-char Base32 label produced by BuildQNAME
// back into the target IP string and Unix timestamp.
//
// Expected payload layout (32 bytes):
//
//	IPv4: [0x04][4-byte IP][8-byte TS big-endian][19 random filler]
//	IPv6: [0x06][16-byte IP][8-byte TS big-endian][7 random filler]
func DecodeBase32Payload(label string) (targetIP string, ts int64, err error) {
	upper := strings.ToUpper(label) // Fix #1: handle DNS 0x20 case randomization
	if len(upper) < payloadBase32Len {
		return "", 0, fmt.Errorf("label too short: got %d chars, need %d", len(upper), payloadBase32Len)
	}
	upper = upper[:payloadBase32Len] // Fix #2: strip DKIM camouflage suffix
	payload, err := Codec.DecodeString(upper)
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
