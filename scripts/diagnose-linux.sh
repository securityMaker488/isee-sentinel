#!/usr/bin/env bash
# Leitura local somente. Nao instala, usa sudo, muda servicos ou consulta a rede.
set -u
export LC_ALL=C

section() { printf '\n== %s ==\n' "$1"; }
run_if_present() {
  if command -v "$1" >/dev/null 2>&1; then
    "$@" 2>&1 || printf 'Nao foi possivel concluir: %s\n' "$1"
  else
    printf 'Nao encontrado no PATH: %s\n' "$1"
  fi
}

case "$(uname -s 2>/dev/null)" in
  Linux) ;;
  *) printf 'Execute este diagnostico no Linux real (Debian13/Ubuntu); ambiente atual nao e Linux.\n' >&2; exit 1 ;;
esac

section 'Momento UTC e sistema'
date -u '+%Y-%m-%dT%H:%M:%SZ'
if [ -r /etc/os-release ]; then
  # Nao executar/source o arquivo de identificacao; mostrar somente campos uteis.
  awk -F= '/^(NAME|VERSION|ID|VERSION_ID|PRETTY_NAME)=/ {print}' /etc/os-release
fi
uname -srmo
if [ -r /etc/arch-release ]; then printf 'Arquivo /etc/arch-release presente.\n'; fi

section 'CPU e virtualizacao'
if command -v lscpu >/dev/null 2>&1; then
  lscpu | awk -F: '/^(Architecture|CPU\(s\)|Model name|Thread\(s\) per core|Core\(s\) per socket|Socket\(s\)|Virtualization|Hypervisor vendor):/ {print}'
else
  printf 'lscpu indisponivel.\n'
fi
run_if_present systemd-detect-virt
if [ -e /dev/kvm ]; then
  printf '/dev/kvm existe; '
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then printf 'usuario tem leitura/escrita.\n'; else printf 'acesso do usuario limitado.\n'; fi
else
  printf '/dev/kvm nao encontrado; KVM operacional nao demonstrado.\n'
fi

section 'Memoria'
run_if_present free -h

section 'Armazenamento (diretorio atual e raiz; sem inventario de arquivos pessoais)'
df -hP / .
df -iP / .

section 'GPU (identificacao sem teste de aceleracao)'
if command -v lspci >/dev/null 2>&1; then
  lspci | awk '/VGA|3D controller|Display controller/ {print}'
else
  printf 'lspci indisponivel.\n'
fi
if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>&1 || true
fi

section 'Ferramentas'
run_if_present node --version
run_if_present npm --version
run_if_present python3 --version
run_if_present rustc --version
run_if_present cargo --version
run_if_present git --version
run_if_present psql --version
run_if_present pg_config --version
run_if_present qemu-system-x86_64 --version
run_if_present systemctl --version

section 'Conclusao'
printf 'Coleta somente leitura finalizada. Nenhuma instalacao, alteracao de particao ou servico foi realizada.\n'
printf 'Versoes e capacidade nao provam hardening, TLS, backups, funcionamento KVM ou homologacao do Sentinel.\n'
