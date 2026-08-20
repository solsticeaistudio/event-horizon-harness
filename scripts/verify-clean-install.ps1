$ErrorActionPreference = "Stop"

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$TemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("event-horizon-clean-" + [guid]::NewGuid().ToString("N"))
$Checkout = Join-Path $TemporaryRoot "repository"
$VirtualEnvironment = Join-Path $TemporaryRoot "venv"
$ExpectedPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())

try {
    New-Item -ItemType Directory -Path $TemporaryRoot | Out-Null
    git clone --quiet --no-local $RepositoryRoot $Checkout
    if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
    Push-Location $Checkout
    try {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
        python -m venv $VirtualEnvironment
        $env:PATH = (Join-Path $VirtualEnvironment "Scripts") + [IO.Path]::PathSeparator + $env:PATH
        python -m pip install --disable-pip-version-check -e ".[test]"
        if ($LASTEXITCODE -ne 0) { throw "Python installation failed" }
        npm run build
        if ($LASTEXITCODE -ne 0) { throw "build failed" }
        npm test
        if ($LASTEXITCODE -ne 0) { throw "tests failed" }
        npm run demo
        if ($LASTEXITCODE -ne 0) { throw "demo failed" }
        python scripts/verify_capability_vectors.py
        if ($LASTEXITCODE -ne 0) { throw "capability vector verification failed" }
        python scripts/verify_certificate.py examples/reference-run/containment-certificate.json --trusted-key examples/reference-run/certificate-signer-public.pem
        if ($LASTEXITCODE -ne 0) { throw "certificate verification failed" }
        python scripts/check_repository_policy.py
        if ($LASTEXITCODE -ne 0) { throw "repository policy check failed" }
    }
    finally {
        Pop-Location
    }
}
finally {
    $ResolvedTemporaryRoot = [IO.Path]::GetFullPath($TemporaryRoot)
    if ($ResolvedTemporaryRoot.StartsWith($ExpectedPrefix) -and (Test-Path -LiteralPath $ResolvedTemporaryRoot)) {
        Remove-Item -LiteralPath $ResolvedTemporaryRoot -Recurse -Force
    }
}
