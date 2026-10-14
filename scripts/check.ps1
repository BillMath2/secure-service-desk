$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    & .\.venv\Scripts\ruff.exe check .
    if ($LASTEXITCODE -ne 0) { throw 'Lint failed' }
    & .\.venv\Scripts\ruff.exe format --check .
    if ($LASTEXITCODE -ne 0) { throw 'Format check failed' }
    & .\.venv\Scripts\mypy.exe
    if ($LASTEXITCODE -ne 0) { throw 'Type check failed' }
    $testDirectory = Join-Path $root ('.lab/pytest-' + [guid]::NewGuid().ToString('N'))
    & .\.venv\Scripts\python.exe -m pytest --tb=short -p no:cacheprovider --basetemp $testDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
} finally {
    Pop-Location
}
