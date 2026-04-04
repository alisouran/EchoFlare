package payload

import (
	"strings"
	"testing"
	"time"
)

// TestRoundTripIPv4 verifies that an IPv4 address encoded by BuildQNAME can be
// recovered by DecodeBase32Payload with the correct IP and an approximately
// correct timestamp.
func TestRoundTripIPv4(t *testing.T) {
	const domain = "scan.example.com"
	const rawIP = "8.8.8.8"

	before := time.Now().Unix()
	fqdn, err := BuildQNAME(rawIP, domain)
	after := time.Now().Unix()
	if err != nil {
		t.Fatalf("BuildQNAME(%q, %q): %v", rawIP, domain, err)
	}

	// fqdn looks like "<52-char-label>.scan.example.com."
	// Strip the trailing domain suffix to isolate the label.
	suffix := "." + domain + "."
	if !strings.HasSuffix(fqdn, suffix) {
		t.Fatalf("FQDN %q does not end with suffix %q", fqdn, suffix)
	}
	label := strings.TrimSuffix(fqdn, suffix)

	gotIP, gotTS, err := DecodeBase32Payload(label)
	if err != nil {
		t.Fatalf("DecodeBase32Payload(%q): %v", label, err)
	}
	if gotIP != rawIP {
		t.Errorf("IP mismatch: got %q, want %q", gotIP, rawIP)
	}
	if gotTS < before || gotTS > after {
		t.Errorf("timestamp %d out of expected range [%d, %d]", gotTS, before, after)
	}
}

// TestRoundTripIPv6 verifies the same contract for an IPv6 address.
func TestRoundTripIPv6(t *testing.T) {
	const domain = "scan.example.com"
	// Use the canonical string form that net.IP.String() produces.
	const rawIP = "2001:db8::1"

	fqdn, err := BuildQNAME(rawIP, domain)
	if err != nil {
		t.Fatalf("BuildQNAME(%q, %q): %v", rawIP, domain, err)
	}

	suffix := "." + domain + "."
	label := strings.TrimSuffix(fqdn, suffix)

	gotIP, _, err := DecodeBase32Payload(label)
	if err != nil {
		t.Fatalf("DecodeBase32Payload(%q): %v", label, err)
	}
	if gotIP != rawIP {
		t.Errorf("IP mismatch: got %q, want %q", gotIP, rawIP)
	}
}

// TestLabelUniqueness verifies that two calls for the same IP produce
// different labels (due to random filler bytes).
func TestLabelUniqueness(t *testing.T) {
	const domain = "scan.example.com"
	const rawIP = "1.2.3.4"

	a, err := BuildQNAME(rawIP, domain)
	if err != nil {
		t.Fatalf("first BuildQNAME: %v", err)
	}
	b, err := BuildQNAME(rawIP, domain)
	if err != nil {
		t.Fatalf("second BuildQNAME: %v", err)
	}
	if a == b {
		t.Error("two calls with the same IP produced identical FQDNs (random filler not working)")
	}
}

// TestDecodeInvalidBase32 verifies that garbage input returns a clear error.
func TestDecodeInvalidBase32(t *testing.T) {
	_, _, err := DecodeBase32Payload("!!!not-base32!!!")
	if err == nil {
		t.Error("expected error for invalid base32 input, got nil")
	}
}
