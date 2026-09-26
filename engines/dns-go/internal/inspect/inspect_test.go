package inspect

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"https://example.com/path?q=1", "example.com", 0},
		{"http://user:pass@Example.COM:8080/a", "example.com", 8080},
		{"example.com", "example.com", 0},
		{"example.com:443", "example.com", 443},
		{"  https://sub.example.com/  ", "sub.example.com", 0},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443},
		{"2001:db8::1", "2001:db8::1", 0},
	}
	for _, c := range cases {
		got := NormalizeTarget(c.in)
		if got.Host != c.wantHost || got.Port != c.wantPort {
			t.Errorf("NormalizeTarget(%q) = {%q,%d}, want {%q,%d}",
				c.in, got.Host, got.Port, c.wantHost, c.wantPort)
		}
	}
}

func TestExtractTitle(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{"<html><head><TITLE>  Hello\n  World </TITLE></head>", "Hello World"},
		{"<title>Only</title>", "Only"},
		{"<title data-x='y'>Attr</title>", "Attr"},
		{"no title here", ""},
	}
	for _, c := range cases {
		if got := ExtractTitle([]byte(c.body)); got != c.want {
			t.Errorf("ExtractTitle(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}

func TestDedupe(t *testing.T) {
	got := Dedupe([]string{"b.com", "A.com", "a.com", "", "  ", "b.com"})
	want := []string{"A.com", "b.com"}
	if len(got) != len(want) {
		t.Fatalf("Dedupe len = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Dedupe[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRelatedHost(t *testing.T) {
	cases := []struct {
		cand, base string
		want       bool
	}{
		{"example.com", "example.com", true},
		{"api.example.com", "example.com", true},
		{"*.example.com", "example.com", true},
		{"example.com", "api.example.com", true}, // apex relative to a sub
		{"evil.com", "example.com", false},
		{"notexample.com", "example.com", false},
		{"", "example.com", false},
	}
	for _, c := range cases {
		if got := RelatedHost(c.cand, c.base); got != c.want {
			t.Errorf("RelatedHost(%q,%q) = %v, want %v", c.cand, c.base, got, c.want)
		}
	}
}

func TestTLSVersionName(t *testing.T) {
	if TLSVersionName(0x0304) != "TLS 1.3" {
		t.Errorf("expected TLS 1.3 for 0x0304")
	}
	if got := TLSVersionName(0x9999); got != "0x9999" {
		t.Errorf("unknown version should print hex, got %q", got)
	}
}

func TestDescribeCert(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "example.com"},
		Issuer:             pkix.Name{CommonName: "Test CA"},
		NotBefore:          now.Add(-24 * time.Hour),
		NotAfter:           now.Add(10 * 24 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
		SerialNumber:       big.NewInt(42),
		DNSNames:           []string{"example.com", "www.example.com", "example.com"},
	}
	md := DescribeCert(cert, now)
	if md["subject"] != "example.com" || md["issuer"] != "Test CA" {
		t.Errorf("subject/issuer wrong: %v", md)
	}
	if md["days_until_expiry"] != "10" {
		t.Errorf("days_until_expiry = %q, want 10", md["days_until_expiry"])
	}
	if md["san_dns_names"] != "example.com, www.example.com" {
		t.Errorf("san dedupe wrong: %q", md["san_dns_names"])
	}
	if _, expired := md["expired"]; expired {
		t.Errorf("valid cert should not be marked expired")
	}

	// Expired cert path.
	cert.NotAfter = now.Add(-1 * time.Hour)
	if md := DescribeCert(cert, now); md["expired"] != "true" {
		t.Errorf("expired cert should be flagged, got %v", md)
	}
}
