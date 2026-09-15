$ErrorActionPreference = "Stop"

# Ensure target directory exists
New-Item -ItemType Directory -Force -Path "internal/proto"

# The go/bin path needs to be in PATH for the protoc plugins to work.
$env:PATH += ";$env:USERPROFILE\go\bin"

# Call the downloaded protoc
& "..\..\.bin\protoc\bin\protoc.exe" `
    --go_out=internal/proto --go_opt=paths=source_relative `
    --go-grpc_out=internal/proto --go-grpc_opt=paths=source_relative `
    --proto_path=..\..\contracts\v1 `
    ..\..\contracts\v1\events.proto

Write-Host "Go protobuf bindings generated successfully."
