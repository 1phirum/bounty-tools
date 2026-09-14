# BugTools Worker IPC Protocol (Version 1)

Workers communicate with the Rust controller via standard I/O (stdin/stdout) exchanging newline-delimited JSON objects.

## Version Contract
Every payload includes `"protocol_version": 1`.

## Messages

### 1. Job Request (Rust -> Worker)
```json
{
  "protocol_version": 1,
  "type": "job",
  "id": "job-1234",
  "module": "dns",
  "target": "example.com",
  "config": {
    "rate_limit_rps": 5.0
  }
}
```

### 2. Progress Event (Worker -> Rust)
```json
{
  "protocol_version": 1,
  "type": "progress",
  "job_id": "job-1234",
  "progress": 45.0,
  "step": "Resolving authoritative nameservers...",
  "requests_sent": 12
}
```

### 3. Job Result (Worker -> Rust)
```json
{
  "protocol_version": 1,
  "type": "result",
  "job_id": "job-1234",
  "status": "completed",
  "findings": [
    {
      "target": "example.com",
      "host": "api.example.com",
      "ip": "104.21.48.192",
      "title": "Resolved Host",
      "description": "Host api.example.com resolves to 104.21.48.192"
    }
  ]
}
```
