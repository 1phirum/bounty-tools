package protocol

// ProtocolVersion specifies the versioned contract between Rust and Go
const ProtocolVersion = 1

type MessageType string

const (
	TypeJob      MessageType = "job"
	TypeProgress MessageType = "progress"
	TypeResult   MessageType = "result"
	TypeError    MessageType = "error"
)

type JobRequest struct {
	ProtocolVersion int                    `json:"protocol_version"`
	Type            MessageType            `json:"type"`
	ID              string                 `json:"id"`
	Module          string                 `json:"module"`
	Target          string                 `json:"target"`
	Config          map[string]interface{} `json:"config,omitempty"`
}

type ProgressUpdate struct {
	ProtocolVersion int         `json:"protocol_version"`
	Type            MessageType `json:"type"`
	JobID           string      `json:"job_id"`
	Progress        float64     `json:"progress"`
	Step            string      `json:"step"`
	RequestsSent    int64       `json:"requests_sent"`
}

type FindingEvent struct {
	Target      string `json:"target"`
	Host        string `json:"host"`
	IP          string `json:"ip,omitempty"`
	Port        int    `json:"port,omitempty"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

type JobResult struct {
	ProtocolVersion int            `json:"protocol_version"`
	Type            MessageType    `json:"type"`
	JobID           string         `json:"job_id"`
	Status          string         `json:"status"`
	Findings        []FindingEvent `json:"findings,omitempty"`
	Error           string         `json:"error,omitempty"`
}
