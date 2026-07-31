$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    foreach ($command in @(
        { go fmt ./... },
        { go mod tidy },
        { go vet ./... },
        { go test ./... -count=1 },
        { go build -trimpath -o bin/h1-racer-kernel.exe ./cmd/h1-racer-kernel }
    )) {
        & $command
        if ($LASTEXITCODE -ne 0) {
            throw "verification command failed with exit code $LASTEXITCODE"
        }
    }

    Write-Host "verified: bin/h1-racer-kernel.exe"
}
finally {
    Pop-Location
}
