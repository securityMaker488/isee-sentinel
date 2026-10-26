#!/usr/bin/env bash
set -euo pipefail
sentinel_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' 'Node.js 24 não encontrado. Instale essa linha e reabra o terminal.' >&2
  exit 1
fi
exec node "$sentinel_script_dir/doctor.mjs" "$@"
