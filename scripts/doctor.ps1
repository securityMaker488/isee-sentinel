[CmdletBinding()]
param([switch]$Json, [switch]$RequireReady)
$ErrorActionPreference = 'Stop'
$nodeCommand = Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $nodeCommand) {
    Write-Error 'Node.js 24 não encontrado. Instale essa linha e reabra o terminal.'
    exit 1
}
$doctorArguments = @((Join-Path $PSScriptRoot 'doctor.mjs'))
if ($Json) { $doctorArguments += '--json' }
if ($RequireReady) { $doctorArguments += '--require-ready' }
& $nodeCommand.Source @doctorArguments
exit $LASTEXITCODE
