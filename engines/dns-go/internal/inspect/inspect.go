// Package inspect holds the pure, side-effect-free helpers the DNS engine
// relies on: target normalization, HTML title extraction, TLS version naming,
// certificate summarization and deduplication. Keeping them free of network
// calls makes them unit-testable in isolation.
package inspect

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Target is a normalized host/port pair parsed from a raw target string.
type Target struct {
	Host string
	Port int
}

// NormalizeTarget strips any scheme, path, query and userinfo from a raw
// target and splits out an explicit port. "https://ex.com:8443/a?b" becomes
// {Host: "ex.com", Port: 8443}; a bare host yields Port 0.
func NormalizeTarget(raw string) Target {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Drop path / query / fragment.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Drop userinfo (user:pass@host).
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	host := s
	port := 0
	// Bracketed IPv6 literal, optionally with a port: [::1]:443
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end >= 0 {
			host = s[1:end]
			rest := s[end+1:]
			if strings.HasPrefix(rest, ":") {
				port = atoi(rest[1:])
			}
			return Target{Host: strings.ToLower(host), Port: port}
		}
	}
	// host:port — but only treat a single trailing colon as a port so we do
	// not mangle a bare IPv6 address with multiple colons.
	if strings.Count(s, ":") == 1 {
		parts := strings.SplitN(s, ":", 2)
		host = parts[0]
		port = atoi(parts[1])
	}
	return Target{Host: strings.ToLower(host), Port: port}
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var wsRe = regexp.MustCompile(`\s+`)

// ExtractTitle returns the collapsed text of the first <title> element, or ""
// if the body has none. The match is case-insensitive and dotall.
func ExtractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	title := wsRe.ReplaceAllString(string(m[1]), " ")
	return strings.TrimSpace(title)
}

// TLSVersionName maps a tls.Version* constant to a human label.
func TLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// DescribeCert summarizes the security-relevant fields of a leaf certificate
// into a flat string map suitable for FindingEvent.Metadata.
func DescribeCert(cert *x509.Certificate, now time.Time) map[string]string {
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	md := map[string]string{
		"subject":             cert.Subject.CommonName,
		"issuer":              cert.Issuer.CommonName,
		"not_before":          cert.NotBefore.UTC().Format(time.RFC3339),
		"not_after":           cert.NotAfter.UTC().Format(time.RFC3339),
		"days_until_expiry":   fmt.Sprintf("%d", daysLeft),
		"signature_algorithm": cert.SignatureAlgorithm.String(),
		"serial":              cert.SerialNumber.String(),
	}
	if len(cert.DNSNames) > 0 {
		md["san_dns_names"] = strings.Join(Dedupe(cert.DNSNames), ", ")
	}
	if cert.NotAfter.Before(now) {
		md["expired"] = "true"
	}
	return md
}

// Dedupe returns the unique, sorted, non-empty entries of in (case-folded for
// comparison but preserving the first-seen spelling).
func Dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		key := strings.ToLower(s)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// RelatedHost reports whether candidate is the apex, a subdomain, or a
// wildcard sibling of base — used to decide whether a SAN entry is a
// meaningful in-scope discovery rather than noise.
func RelatedHost(candidate, base string) bool {
	c := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(candidate, "*."), "."))
	b := strings.ToLower(strings.TrimSuffix(base, "."))
	if c == "" || b == "" {
		return false
	}
	return c == b || strings.HasSuffix(c, "."+b) || strings.HasSuffix(b, "."+c)
}
