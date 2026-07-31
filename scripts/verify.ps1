$ErrorActionPreference = "Stop"
go fmt ./...
go mod tidy
go vet ./...
go test ./... -count=1
go build -trimpath -o bin/h1-racer-kernel.exe ./cmd/h1-racer-kernel
Write-Host "verified: bin/h1-racer-kernel.exe"