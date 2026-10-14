param(
    [ValidateSet('Start', 'Check', 'Stop')][string]$Action = 'Start',
    [string]$DockerPath = 'docker'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
function Invoke-Checked {
    param([string]$Program, [string[]]$CommandArgs)
    & $Program @CommandArgs
    if ($LASTEXITCODE -ne 0) { throw "Phase 4 command failed: $Program" }
}
function Compose {
    param([string]$Project, [string[]]$CommandArgs)
    Invoke-Checked $DockerPath (@('compose', '-f', "infra/compose.$Project.yaml") + $CommandArgs)
}
$python = Join-Path $root '.venv/Scripts/python.exe'
$oldIntegration = $env:DESK_READ_INTEGRATION
try {
    if ($Action -eq 'Stop') {
        foreach ($project in @('phase4', 'phase3-app', 'phase3-reads', 'phase2-model', 'phase2-identity', 'phase2-reads')) {
            Compose $project @('down')
        }
    } elseif ($Action -eq 'Start') {
        Invoke-Checked $python @('scripts/prepare_phase2.py')
        Invoke-Checked $python @('scripts/prepare_read_store.py')
        Compose 'phase2-reads' @('up', '-d', '--wait', '--pull', 'never')
        Invoke-Checked $python @('scripts/prepare_read_store.py', '--apply')
        Compose 'phase2-identity' @('up', '-d', '--pull', 'never')
        Invoke-Checked $python @('scripts/wait_identity.py')
        Compose 'phase2-model' @('up', '-d', '--pull', 'never')
        Invoke-Checked $python @('scripts/check_model_boundary.py', '--docker', $DockerPath)
        Invoke-Checked $python @('scripts/prepare_isolated_reads.py')
        Invoke-Checked $python @('-m', 'scripts.prepare_phase3_app', '--provider', 'local')
        Invoke-Checked $python @('-m', 'scripts.prepare_phase4')
        Compose 'phase3-app' @('stop', 'browser', 'agent')
        Compose 'phase3-reads' @('up', '-d', '--pull', 'never')
        Invoke-Checked $python @('scripts/check_isolated_reads.py', '--docker', $DockerPath)
        Compose 'phase3-app' @('up', '-d', '--pull', 'never', 'publisher')
        Compose 'phase4' @('up', '-d', '--pull', 'never')
        Invoke-Checked $python @('scripts/check_phase4_boundary.py', '--docker', $DockerPath)
        Write-Host 'Phase 4 ready: https://127.0.0.1:19481/access (local CA trust required).'
    } else {
        # Integration fixtures mutate the disposable database. Stop all background
        # executors/delivery/reconciliation before the suite, then restore services.
        Compose 'phase4' @('stop')
        try {
            $env:DESK_READ_INTEGRATION = '1'
            & "$PSScriptRoot/check.ps1"
        } finally {
            Compose 'phase4' @('up', '-d', '--pull', 'never')
        }
        foreach ($probe in @('check_phase4_network', 'check_phase4_workflows', 'check_phase4_model', 'check_phase4_logs')) {
            Invoke-Checked $python @("scripts/$probe.py", '--docker', $DockerPath)
        }
    }
} finally {
    $env:DESK_READ_INTEGRATION = $oldIntegration
    Pop-Location
}
