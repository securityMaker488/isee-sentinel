[CmdletBinding()]
param([switch]$RunTests)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$sentinelRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
function Invoke-SentinelCommand {
    param([string]$Command, [string[]]$ArgumentList)
    & $Command @ArgumentList
    if ($LASTEXITCODE -ne 0) { throw "Falha na etapa: $Command (código $LASTEXITCODE)." }
}
if (-not (Get-Command node -CommandType Application -ErrorAction SilentlyContinue)) {
    throw 'Node.js 24 não encontrado. Instale essa linha e reabra o terminal.'
}
Push-Location -LiteralPath $sentinelRoot
try {
    Invoke-SentinelCommand 'node' @('scripts/doctor.mjs')
    Invoke-SentinelCommand 'npm.cmd' @('ci', '--ignore-scripts')
    Invoke-SentinelCommand 'npm.cmd' @('run', 'build')
    Invoke-SentinelCommand 'cargo' @('build', '--locked', '--manifest-path', 'packages/endpoint-agent/Cargo.toml')
    if ($RunTests) {
        Invoke-SentinelCommand 'npm.cmd' @('test')
        Invoke-SentinelCommand 'cargo' @('test', '--locked', '--manifest-path', 'packages/endpoint-agent/Cargo.toml')
        $diagnosticJson = & node scripts/doctor.mjs --json
        if ($LASTEXITCODE -ne 0) { throw 'Diagnóstico final não passou.' }
        $pythonExecutable = ($diagnosticJson | ConvertFrom-Json).tools.python.path
        Invoke-SentinelCommand $pythonExecutable @('-m', 'unittest', 'discover', '-s', 'workers/integrity', '-p', 'test_*.py')
        Invoke-SentinelCommand $pythonExecutable @('-m', 'unittest', 'discover', '-s', 'workers/forensics', '-p', 'test_*.py')
        Invoke-SentinelCommand $pythonExecutable @('-m', 'unittest', 'discover', '-s', 'workers/imports', '-p', 'test_*.py')
    }
    Invoke-SentinelCommand 'node' @('scripts/doctor.mjs', '--require-ready')
    Write-Host 'Preparação concluída. O banco e a identidade do operador devem ser provisionados conforme a documentação.'
} finally { Pop-Location }
