param()

Write-Host "Probing https://hyperagent.com/api/mcp..."

# 1. Test GET (Standard SSE connection)
Write-Host "`n--- Testing GET (SSE / HTTP) ---"
try {
    $resp = Invoke-WebRequest -Uri "https://hyperagent.com/api/mcp" -Method Get -TimeoutSec 10 -Headers @{ "Accept" = "text/event-stream, application/json, */*" } -ErrorAction Stop
    Write-Host "HTTP Status: $($resp.StatusCode)"
    Write-Host "Content-Type: $($resp.Headers['Content-Type'])"
    Write-Host "Body Preview: $($resp.Content.Substring(0, [Math]::Min(200, $resp.Content.Length)))"
} catch {
    Write-Host "GET Failed/Returned Error: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        if ($stream) {
            $reader = New-Object System.IO.StreamReader($stream)
            $body = $reader.ReadToEnd()
            Write-Host "Response Body: $body"
        }
    }
}

# 2. Test POST (JSON-RPC initialize test)
Write-Host "`n--- Testing POST (JSON-RPC Initialize) ---"
$initPayload = @{
    jsonrpc = "2.0"
    id = 1
    method = "initialize"
    params = @{
        protocolVersion = "2024-11-05"
        capabilities = @{}
        clientInfo = @{
            name = "antigravity"
            version = "1.0.0"
        }
    }
} | ConvertTo-Json

try {
    $postResp = Invoke-WebRequest -Uri "https://hyperagent.com/api/mcp" -Method Post -Body $initPayload -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
    Write-Host "HTTP Status: $($postResp.StatusCode)"
    Write-Host "Content-Type: $($postResp.Headers['Content-Type'])"
    Write-Host "Response Body: $($postResp.Content)"
} catch {
    Write-Host "POST Failed/Returned Error: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        if ($stream) {
            $reader = New-Object System.IO.StreamReader($stream)
            $body = $reader.ReadToEnd()
            Write-Host "Response Body: $body"
        }
    }
}
