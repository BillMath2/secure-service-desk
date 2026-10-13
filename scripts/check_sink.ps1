$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $network = docker network inspect service-desk-phase0_test_only | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $network[0].Internal) { throw 'Sink network must be internal' }
    $containerId = docker compose -f infra/compose.phase0.yaml ps -q sink
    if ($LASTEXITCODE -ne 0 -or -not $containerId) { throw 'Sink is not running' }
    $container = docker inspect $containerId | ConvertFrom-Json
    if ($container[0].HostConfig.PortBindings.PSObject.Properties.Count -gt 0) { throw 'Sink must not publish ports' }
    @'
import json, socket, urllib.request
assert urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).status == 200
request = urllib.request.Request('http://127.0.0.1:8080/capture', data=b'synthetic-probe', method='POST')
with urllib.request.urlopen(request, timeout=3) as response:
    assert response.status == 204 and response.read() == b''
try:
    connection = socket.create_connection(('1.1.1.1', 443), timeout=2)
except OSError:
    pass
else:
    connection.close()
    raise RuntimeError('Unexpected external egress')
print(json.dumps({'local_capture': True, 'response_has_no_payload': True, 'external_tcp_denied': True}))
'@ | docker compose -f infra/compose.phase0.yaml exec -T sink /app/.venv/bin/python -
    if ($LASTEXITCODE -ne 0) { throw 'Sink network probe failed' }
    New-Item -ItemType Directory -Force -Path reports | Out-Null
    [ordered]@{ internal_network = $true; no_published_ports = $true; local_capture = $true; external_tcp_denied = $true } |
        ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath reports/phase0-sink.json
} finally {
    Pop-Location
}
