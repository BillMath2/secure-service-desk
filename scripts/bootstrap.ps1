$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $uv = Join-Path $root '.tools\uv\uv.exe'
    if (-not (Test-Path -LiteralPath $uv)) {
        New-Item -ItemType Directory -Force -Path '.tools' | Out-Null
        Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/astral-sh/uv/releases/download/0.13.0/uv-x86_64-pc-windows-msvc.zip' -OutFile '.tools\uv.zip'
        Expand-Archive -LiteralPath '.tools\uv.zip' -DestinationPath '.tools\uv' -Force
    }
    $env:UV_PYTHON_INSTALL_DIR = Join-Path $root '.tools\python'
    $env:UV_PYTHON_BIN_DIR = Join-Path $root '.tools\bin'
    $env:UV_CACHE_DIR = Join-Path $root '.tools\uv-cache'
    & $uv sync --locked
    if ($LASTEXITCODE -ne 0) { throw 'Dependency setup failed' }
} finally {
    Pop-Location
}
