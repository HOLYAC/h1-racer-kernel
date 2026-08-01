param(
    [ValidateRange(1, 1000)][int]$Rounds = 100
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$oldEnabled = $env:H1_RACER_SOAK
$oldRounds = $env:H1_RACER_SOAK_ROUNDS
try {
    $env:H1_RACER_SOAK = "1"
    $env:H1_RACER_SOAK_ROUNDS = $Rounds.ToString()
    Push-Location $root
    try {
        go test ./internal/race -run '^TestAuthorizedNetworkSoak$' -count=1 -v
        if ($LASTEXITCODE -ne 0) {
            throw "network soak failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:H1_RACER_SOAK = $oldEnabled
    $env:H1_RACER_SOAK_ROUNDS = $oldRounds
}
