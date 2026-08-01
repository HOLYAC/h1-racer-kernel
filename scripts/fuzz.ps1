param(
    [ValidateRange(1, 3600)]
    [int]$Seconds = 15
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    go test `
        ./internal/framing `
        -run '^$' `
        -fuzz '^FuzzSplitRequest$' `
        -fuzztime "${Seconds}s"
    if ($LASTEXITCODE -ne 0) {
        throw "framing fuzzing failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
