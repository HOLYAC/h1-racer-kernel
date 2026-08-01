$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $PSScriptRoot
$onWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$exeSuffix = if ($onWindows) { ".exe" } else { "" }
$kernelOutput = Join-Path $root ("bin\h1-racer-kernel" + $exeSuffix)
$artifactOutput = Join-Path $root ("bin\h1-racer-artifact" + $exeSuffix)
$receiverOutput = Join-Path $root ("bin\h1-racer-receiver" + $exeSuffix)

Push-Location $root
try {
    $unformatted = @(gofmt -l .)
    if ($LASTEXITCODE -ne 0) {
        throw "gofmt inspection failed with exit code $LASTEXITCODE"
    }
    if ($unformatted.Count -ne 0) {
        throw "Go formatting drift: $($unformatted -join ', ')"
    }

    go mod tidy
    if ($LASTEXITCODE -ne 0) {
        throw "go mod tidy failed with exit code $LASTEXITCODE"
    }
    git diff --exit-code -- go.mod go.sum
    if ($LASTEXITCODE -ne 0) {
        throw "go.mod or go.sum drifted after go mod tidy"
    }

    foreach ($command in @(
        { go vet ./... },
        { go test ./... -count=1 },
        { go build -mod=readonly -trimpath -buildvcs=false -ldflags "-buildid=" -o $kernelOutput ./cmd/h1-racer-kernel },
        { go build -mod=readonly -trimpath -buildvcs=false -ldflags "-buildid=" -o $artifactOutput ./cmd/h1-racer-artifact },
        { go build -mod=readonly -trimpath -buildvcs=false -ldflags "-buildid=" -o $receiverOutput ./cmd/h1-racer-receiver }
    )) {
        & $command
        if ($LASTEXITCODE -ne 0) {
            throw "verification command failed with exit code $LASTEXITCODE"
        }
    }

    Write-Host "verified: $kernelOutput"
    Write-Host "verified: $artifactOutput"
    Write-Host "verified: $receiverOutput"
}
finally {
    Pop-Location
}
