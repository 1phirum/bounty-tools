// Command dns is BugTools' DNS reconnaissance engine. It reads a single
// JobRequest as JSON on stdin and streams ProgressUpdate / JobResult JSON on
// stdout, matching the recon-go contract.
//
// For one target it performs, concurrently:
//   - DNS enumeration: A, AAAA, CNAME, MX, NS, TXT, SRV, and reverse PTR of
//     every resolved address.
//   - TLS/HTTPS inspection: dials :443 (or the target's port), reads the leaf
//     certificate and reports issuer, validity window, signature algorithm,
//     negotiated version/cipher, and — importantly for recon — every SAN
//     hostname, surfacing in-scope SANs as newly discovered subdomains.
//   - HTTP(S) probing: fetches https:// then http:// and reports status,
//     Server header, final redirected URL, and page <title>.
//
// Everything is read-only and scoped to the single target supplied by the
// caller; the tool resolves and connects but never mutates the target.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bugtools/bugtools/engines/dns-go/internal/inspect"
	"github.com/bugtools/bugtools/engines/dns-go/pkg/protocol"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	// DNS/TXT payloads and cert SANs can be large; grow the line budget.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	if !scanner.Scan() {
		return
	}

	var req protocol.JobRequest
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		sendError("unknown", fmt.Sprintf("invalid json payload: %v", err))
		return
	}
	if req.ProtocolVersion != protocol.ProtocolVersion {
		sendError(req.ID, fmt.Sprintf("protocol version mismatch: expected %d, got %d",
			protocol.ProtocolVersion, req.ProtocolVersion))
		return
	}
	runJob(req)
}

// runJob orchestrates the three enrichment stages and emits the final result.
func runJob(req protocol.JobRequest) {
	tgt := inspect.NormalizeTarget(req.Target)
	if tgt.Host == "" {
		sendError(req.ID, "could not parse a host from target")
		return
	}

	cfg := parseConfig(req.Config)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.overall)
	defer cancel()

	var (
		mu       sync.Mutex
		findings []protocol.FindingEvent
		requests int64
	)
	add := func(fs ...protocol.FindingEvent) {
		mu.Lock()
		findings = append(findings, fs...)
		mu.Unlock()
	}
	countReq := func(n int64) { mu.Lock(); requests += n; mu.Unlock() }

	sendProgress(req.ID, 10, fmt.Sprintf("Enumerating DNS records for %s...", tgt.Host), 1)

	var wg sync.WaitGroup

	// Stage 1: DNS enumeration.
	wg.Add(1)
	go func() {
		defer wg.Done()
		fs, n := enumerateDNS(ctx, req.Target, tgt.Host, cfg)
		countReq(n)
		add(fs...)
	}()

	// Stage 2: TLS / HTTPS certificate inspection.
	if cfg.tls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			port := tgt.Port
			if port == 0 {
				port = 443
			}
			fs, n := inspectTLS(ctx, req.Target, tgt.Host, port, cfg)
			countReq(n)
			add(fs...)
		}()
	}

	// Stage 3: HTTP(S) probing.
	if cfg.http {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fs, n := probeHTTP(ctx, req.Target, tgt.Host, cfg)
			countReq(n)
			add(fs...)
		}()
	}

	// Report coarse progress while the stages run.
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(400 * time.Millisecond)
		defer ticker.Stop()
		pct := 20.0
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if pct < 85 {
					pct += 10
					mu.Lock()
					r := requests
					mu.Unlock()
					sendProgress(req.ID, pct, "Collecting DNS / TLS / HTTP evidence...", r)
				}
			}
		}
	}()

	wg.Wait()
	close(done)

	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].RecordType < findings[j].RecordType
	})

	sendProgress(req.ID, 100, "DNS reconnaissance completed", requests)
	res := protocol.JobResult{
		ProtocolVersion: protocol.ProtocolVersion,
		Type:            protocol.TypeResult,
		JobID:           req.ID,
		Status:          "completed",
		Findings:        findings,
	}
	emit(res)
}

// config holds the resolved, defaulted knobs for one run.
type config struct {
	tls     bool
	http    bool
	dial    time.Duration
	overall time.Duration
}

func parseConfig(c map[string]interface{}) config {
	cfg := config{
		tls:     cfgBool(c, "enable_tls", true),
		http:    cfgBool(c, "enable_http", true),
		dial:    time.Duration(cfgInt(c, "timeout_secs", 5)) * time.Second,
		overall: time.Duration(cfgInt(c, "overall_timeout_secs", 20)) * time.Second,
	}
	if cfg.dial <= 0 {
		cfg.dial = 5 * time.Second
	}
	if cfg.overall <= 0 {
		cfg.overall = 20 * time.Second
	}
	return cfg
}

// enumerateDNS resolves the common record types and reverse-resolves each IP.
func enumerateDNS(ctx context.Context, target, host string, cfg config) ([]protocol.FindingEvent, int64) {
	r := &net.Resolver{}
	var out []protocol.FindingEvent
	var reqs int64

	rec := func(rtype, value, ip, desc string) protocol.FindingEvent {
		return protocol.FindingEvent{
			Target:      target,
			Host:        host,
			IP:          ip,
			RecordType:  rtype,
			Value:       value,
			Title:       fmt.Sprintf("%s record", rtype),
			Description: desc,
		}
	}

	// A / AAAA.
	reqs++
	if ips, err := r.LookupIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			rtype := "A"
			if ip.To4() == nil {
				rtype = "AAAA"
			}
			out = append(out, rec(rtype, ip.String(), ip.String(),
				fmt.Sprintf("%s resolves to %s", host, ip.String())))

			// Reverse PTR for each address.
			reqs++
			if names, err := r.LookupAddr(ctx, ip.String()); err == nil {
				for _, name := range inspect.Dedupe(names) {
					out = append(out, rec("PTR", strings.TrimSuffix(name, "."), ip.String(),
						fmt.Sprintf("%s reverse-resolves to %s", ip.String(), name)))
				}
			}
		}
	}

	// CNAME.
	reqs++
	if cname, err := r.LookupCNAME(ctx, host); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(cname, host) {
			out = append(out, rec("CNAME", cname, "",
				fmt.Sprintf("%s is a canonical alias for %s", host, cname)))
		}
	}

	// MX.
	reqs++
	if mxs, err := r.LookupMX(ctx, host); err == nil {
		for _, mx := range mxs {
			mxHost := strings.TrimSuffix(mx.Host, ".")
			if mxHost == "" {
				// RFC 7505 "null MX": the domain explicitly accepts no mail.
				out = append(out, rec("MX", ".", "",
					"null MX (RFC 7505): domain explicitly accepts no mail"))
				continue
			}
			out = append(out, rec("MX", mxHost, "",
				fmt.Sprintf("mail exchanger %s (pref %d)", mxHost, mx.Pref)))
		}
	}

	// NS.
	reqs++
	if nss, err := r.LookupNS(ctx, host); err == nil {
		for _, ns := range nss {
			out = append(out, rec("NS", strings.TrimSuffix(ns.Host, "."), "",
				fmt.Sprintf("authoritative name server %s", ns.Host)))
		}
	}

	// TXT (SPF, DMARC hints, verification tokens).
	reqs++
	if txts, err := r.LookupTXT(ctx, host); err == nil {
		for _, txt := range txts {
			f := rec("TXT", txt, "", fmt.Sprintf("TXT record: %s", txt))
			if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
				f.Metadata = map[string]string{"kind": "spf"}
			}
			out = append(out, f)
		}
	}

	// SRV for a couple of ubiquitous services (best-effort).
	for _, svc := range []struct{ service, proto string }{{"_sip", "_tcp"}, {"_xmpp-server", "_tcp"}} {
		reqs++
		if _, addrs, err := r.LookupSRV(ctx, strings.TrimPrefix(svc.service, "_"), strings.TrimPrefix(svc.proto, "_"), host); err == nil {
			for _, a := range addrs {
				out = append(out, rec("SRV", fmt.Sprintf("%s:%d", strings.TrimSuffix(a.Target, "."), a.Port), "",
					fmt.Sprintf("%s.%s service at %s:%d", svc.service, svc.proto, a.Target, a.Port)))
			}
		}
	}

	return out, reqs
}

// inspectTLS dials the target's TLS port and reports certificate and
// handshake details, surfacing in-scope SAN hostnames as discoveries.
func inspectTLS(ctx context.Context, target, host string, port int, cfg config) ([]protocol.FindingEvent, int64) {
	dialer := &net.Dialer{Timeout: cfg.dial}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	// InsecureSkipVerify: recon must inspect invalid/self-signed/expired certs
	// too, so verification is deliberately disabled and reported instead.
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // recon inspects untrusted certs by design
	})
	if err != nil {
		return []protocol.FindingEvent{{
			Target:      target,
			Host:        host,
			Port:        port,
			RecordType:  "TLS",
			Severity:    "info",
			Title:       "TLS handshake failed",
			Description: fmt.Sprintf("could not establish TLS with %s: %v", addr, err),
		}}, 1
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, 1
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()

	md := inspect.DescribeCert(leaf, now)
	md["tls_version"] = inspect.TLSVersionName(state.Version)
	md["cipher_suite"] = tls.CipherSuiteName(state.CipherSuite)
	if state.NegotiatedProtocol != "" {
		md["alpn"] = state.NegotiatedProtocol
	}

	severity := "info"
	if leaf.NotAfter.Before(now) {
		severity = "high"
	} else if leaf.NotAfter.Sub(now) < 14*24*time.Hour {
		severity = "medium"
	}

	out := []protocol.FindingEvent{{
		Target:      target,
		Host:        host,
		Port:        port,
		RecordType:  "TLS",
		Value:       leaf.Subject.CommonName,
		Severity:    severity,
		Title:       fmt.Sprintf("TLS certificate (%s)", md["tls_version"]),
		Description: fmt.Sprintf("issuer=%q expires=%s (%s days)", md["issuer"], md["not_after"], md["days_until_expiry"]),
		Metadata:    md,
	}}

	// Surface in-scope SAN hostnames as discovered subdomains.
	for _, san := range inspect.Dedupe(leaf.DNSNames) {
		if strings.EqualFold(strings.TrimPrefix(san, "*."), host) {
			continue
		}
		if inspect.RelatedHost(san, host) {
			out = append(out, protocol.FindingEvent{
				Target:      target,
				Host:        host,
				RecordType:  "SAN",
				Value:       san,
				Severity:    "info",
				Title:       "Subdomain from certificate SAN",
				Description: fmt.Sprintf("certificate for %s also covers %s", host, san),
			})
		}
	}
	return out, 1
}

// probeHTTP fetches https:// then http:// and reports the response shape.
func probeHTTP(ctx context.Context, target, host string, cfg config) ([]protocol.FindingEvent, int64) {
	client := &http.Client{
		Timeout: cfg.dial,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // recon probe
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: cfg.dial,
		},
	}

	var out []protocol.FindingEvent
	var reqs int64
	for _, scheme := range []string{"https", "http"} {
		reqs++
		url := fmt.Sprintf("%s://%s/", scheme, host)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "bugtools-dns/1.0 (+recon)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		md := map[string]string{
			"scheme":     scheme,
			"status":     fmt.Sprintf("%d", resp.StatusCode),
			"final_url":  resp.Request.URL.String(),
			"server":     resp.Header.Get("Server"),
			"content_ty": resp.Header.Get("Content-Type"),
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			md["location"] = loc
		}
		title := inspect.ExtractTitle(body)
		out = append(out, protocol.FindingEvent{
			Target:      target,
			Host:        host,
			RecordType:  "HTTP",
			Value:       fmt.Sprintf("%d", resp.StatusCode),
			Severity:    "info",
			Title:       fmt.Sprintf("%s %d %s", strings.ToUpper(scheme), resp.StatusCode, title),
			Description: fmt.Sprintf("%s -> %s (server=%q)", url, md["final_url"], md["server"]),
			Metadata:    md,
		})
	}
	return out, reqs
}

func cfgBool(c map[string]interface{}, key string, def bool) bool {
	if c == nil {
		return def
	}
	if v, ok := c[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

func cfgInt(c map[string]interface{}, key string, def int) int {
	if c == nil {
		return def
	}
	if v, ok := c[key]; ok {
		if f, ok := v.(float64); ok { // JSON numbers decode as float64
			return int(f)
		}
	}
	return def
}

func sendProgress(jobID string, pct float64, step string, requests int64) {
	emit(protocol.ProgressUpdate{
		ProtocolVersion: protocol.ProtocolVersion,
		Type:            protocol.TypeProgress,
		JobID:           jobID,
		Progress:        pct,
		Step:            step,
		RequestsSent:    requests,
	})
}

func sendError(jobID, msg string) {
	emit(protocol.JobResult{
		ProtocolVersion: protocol.ProtocolVersion,
		Type:            protocol.TypeError,
		JobID:           jobID,
		Status:          "failed",
		Error:           msg,
	})
}

// emit serializes v as one JSON line to stdout.
func emit(v interface{}) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}
