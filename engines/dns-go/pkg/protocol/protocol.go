// Package protocol defines the versioned stdin/stdout JSON contract this
// engine shares with the Rust coordinator. It mirrors the recon-go engine's
// protocol so the DNS engine is a drop-in sibling, with a few additive,
// omitempty fields (RecordType/Value/Severity/Metadata) that older consumers
// can safely ignore.
package protocol

// ProtocolVersion is the versioned contract between Rust and Go. Bump it only
// on a breaking change to these structs.
const ProtocolVersion = 1

type MessageType string

const (
	TypeJob      MessageType = "job"
	TypeProgress MessageType = "progress"
	TypeResult   MessageType = "result"
	TypeError    MessageType = "error"
)

// JobRequest is the single JSON object read from stdin.
type JobRequest struct {
	ProtocolVersion int                    `json:"protocol_version"`
	Type            MessageType            `json:"type"`
	ID              string                 `json:"id"`
	Module          string                 `json:"module"`
	Target          string                 `json:"target"`
	Config          map[string]interface{} `json:"config,omitempty"`
}

// ProgressUpdate is emitted to stdout as the job advances.
type ProgressUpdate struct {
	ProtocolVersion int         `json:"protocol_version"`
	Type            MessageType `json:"type"`
	JobID           string      `json:"job_id"`
	Progress        float64     `json:"progress"`
	Step            string      `json:"step"`
	RequestsSent    int64       `json:"requests_sent"`
}

// FindingEvent is one discovered fact. Target/Host/IP/Port/Title/Description
// are wire-compatible with recon-go; the remaining fields are additive.
type FindingEvent struct {
	Target      string            `json:"target"`
	Host        string            `json:"host"`
	IP          string            `json:"ip,omitempty"`
	Port        int               `json:"port,omitempty"`
	RecordType  string            `json:"record_type,omitempty"`
	Value       string            `json:"value,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// JobResult is the terminal message: either a completed result with findings
// or a failure carrying Error.
type JobResult struct {
	ProtocolVersion int            `json:"protocol_version"`
	Type            MessageType    `json:"type"`
	JobID           string         `json:"job_id"`
	Status          string         `json:"status"`
	Findings        []FindingEvent `json:"findings,omitempty"`
	Error           string         `json:"error,omitempty"`
}
