#!/usr/bin/env bash
set -euo pipefail
sentinel_run_tests=false
case "${1:-}" in
  '') ;;
  --test) sentinel_run_tests=true ;;
  --help) printf '%s\n' 'Uso: bash scripts/setup-debian.sh [--test]' 'Instala dependências do projeto e compila. Não instala pacotes do sistema, banco, serviços ou partições.'; exit 0 ;;
  *) printf '%s\n' 'Argumento inválido. Use --test ou --help.' >&2; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then printf '%s\n' 'Use somente --test ou --help.' >&2; exit 2; fi
sentinel_repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$sentinel_repo_root"
if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' 'Node.js 24 não encontrado. Instale essa linha e reabra o terminal.' >&2
  exit 1
fi
node scripts/doctor.mjs
npm ci --ignore-scripts
npm run build
cargo build --locked --manifest-path packages/endpoint-agent/Cargo.toml
if "$sentinel_run_tests"; then
  npm test
  cargo test --locked --manifest-path packages/endpoint-agent/Cargo.toml
  sentinel_python="$(node scripts/doctor.mjs --json | node -e 'let data="";process.stdin.on("data",part=>data+=part);process.stdin.on("end",()=>process.stdout.write(JSON.parse(data).tools.python.path));')"
  "$sentinel_python" -m unittest discover -s workers/integrity -p 'test_*.py'
  "$sentinel_python" -m unittest discover -s workers/forensics -p 'test_*.py'
  "$sentinel_python" -m unittest discover -s workers/imports -p 'test_*.py'
fi
node scripts/doctor.mjs --require-ready
printf '%s\n' 'Preparação concluída. O banco e a identidade do operador devem ser provisionados conforme a documentação.'
