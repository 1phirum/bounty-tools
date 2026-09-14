package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/bugtools/bugtools/engines/recon-go/pkg/protocol"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return
	}

	var req protocol.JobRequest
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		sendError("unknown", fmt.Sprintf("invalid json payload: %v", err))
		return
	}

	if req.ProtocolVersion != protocol.ProtocolVersion {
		sendError(req.ID, fmt.Sprintf("protocol version mismatch: expected %d, got %d", protocol.ProtocolVersion, req.ProtocolVersion))
		return
	}

	runJob(req)
}

func sendProgress(jobID string, pct float64, step string, requests int64) {
	evt := protocol.ProgressUpdate{
		ProtocolVersion: protocol.ProtocolVersion,
		Type:            protocol.TypeProgress,
		JobID:           jobID,
		Progress:        pct,
		Step:            step,
		RequestsSent:    requests,
	}
	bytes, _ := json.Marshal(evt)
	fmt.Println(string(bytes))
}

func sendError(jobID string, msg string) {
	res := protocol.JobResult{
		ProtocolVersion: protocol.ProtocolVersion,
		Type:            protocol.TypeError,
		JobID:           jobID,
		Status:          "failed",
		Error:           msg,
	}
	bytes, _ := json.Marshal(res)
	fmt.Println(string(bytes))
}

func runJob(req protocol.JobRequest) {
	sendProgress(req.ID, 10.0, "Parsing target and initializing worker pool...", 1)
	time.Sleep(300 * time.Millisecond)

	targetHost := req.Target
	if strings.Contains(targetHost, "://") {
		parts := strings.Split(targetHost, "://")
		if len(parts) > 1 {
			targetHost = strings.Split(parts[1], "/")[0]
		}
	}
	targetHost = strings.Split(targetHost, ":")[0]

	sendProgress(req.ID, 40.0, fmt.Sprintf("Resolving DNS records for %s...", targetHost), 2)
	ips, err := net.LookupHost(targetHost)

	var findings []protocol.FindingEvent
	if err == nil {
		for _, ip := range ips {
			findings = append(findings, protocol.FindingEvent{
				Target:      req.Target,
				Host:        targetHost,
				IP:          ip,
				Title:       "Resolved Host",
				Description: fmt.Sprintf("Host %s resolves to %s", targetHost, ip),
			})
		}
	}

	sendProgress(req.ID, 85.0, "Formatting reconnaissance findings...", 4)
	time.Sleep(200 * time.Millisecond)

	sendProgress(req.ID, 100.0, "Reconnaissance completed", int64(len(ips)+2))

	res := protocol.JobResult{
		ProtocolVersion: protocol.ProtocolVersion,
		Type:            protocol.TypeResult,
		JobID:           req.ID,
		Status:          "completed",
		Findings:        findings,
	}
	bytes, _ := json.Marshal(res)
	fmt.Println(string(bytes))
}
