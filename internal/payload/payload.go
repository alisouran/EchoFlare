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

	label := Codec.EncodeToString(payload) // always 52 chars, uppercase, no "="
	// dns.Fqdn appends the trailing dot required by the DNS wire format.
	return dns.Fqdn(fmt.Sprintf("%s.%s", label, domain)), nil
}

// DecodeBase32Payload decodes a 52-char Base32 label produced by BuildQNAME
// back into the target IP string and Unix timestamp.
//
// Expected payload layout (32 bytes):
//
//	IPv4: [0x04][4-byte IP][8-byte TS big-endian][19 random filler]
//	IPv6: [0x06][16-byte IP][8-byte TS big-endian][7 random filler]
func DecodeBase32Payload(label string) (targetIP string, ts int64, err error) {
	payload, err := Codec.DecodeString(strings.ToUpper(label))
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
