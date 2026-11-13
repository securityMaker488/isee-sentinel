# Continuidade Windows ↔ Debian13

Este guia transporta código e memória de projeto. Não instala Debian, particiona
discos nem altera Windows/boot. A instalação Debian13KDE exige backup verificado,
identificação de discos e plano próprio antes de qualquer alteração destrutiva.
Os critérios de hardware anteriores estão em docs/FASES-V6.5.md.

## Antes de sair do Windows

1. Finalize ou registre alterações em PROJECT_STATE.md, inclusive testes e bloqueios.
2. Execute a verificação de repositório, revise o diff e faça commit local.
3. Sincronize apenas com o GitHub PRIVADO confirmado. Não envie .env, chaves,
   bancos, credenciais de agente ou autenticação do Codex.
4. Guarde backups de dados/chaves separadamente. Git transporta fonte e memória,
   não credenciais nem a instância operacional.

O remoto criado é `securityMaker488/isee-sentinel`, público desde 13/11/2026 sob
AGPL-3.0. [GITHUB.md](GITHUB.md) registra a preparação e os comandos de conferência. Verifique a sincronização
antes de trocar de sistema; a criação do remoto não encerra as pendências Windows.

Também é possível transportar o Git bundle local da entrega, sem GitHub.
Confira seu SHA-256 e, em uma pasta nova no Debian, use:

```bash
git clone /caminho/isee-sentinel-v6.9-windows-dev.bundle isee-sentinel
cd isee-sentinel
git status
```

Esse clone terá o arquivo bundle como origem local. Configure o GitHub
separadamente quando autorizado; não trate o bundle como endereço de publicação.
O ZIP correspondente contém fonte e build web de desenvolvimento, sem banco,
chaves ou dependências instaladas. Em ambos os casos rode o setup do sistema
destino para reconstruir dependências e agente nativo.

## No Debian já instalado e validado

Instale Git, Node24, Python3.11+ e o toolchain Rust compatível. Execute como
usuário normal; requisitos ausentes serão descritos pelo doctor. Não presuma
que a versão Node oferecida pelo APT atende ao package.json.

Depois de autenticar GitHub CLI com a conta autorizada:
```bash
gh auth login
gh repo view securityMaker488/isee-sentinel --json nameWithOwner,visibility
git clone https://github.com/securityMaker488/isee-sentinel.git
cd isee-sentinel
git status
bash scripts/doctor.sh
bash scripts/setup-debian.sh
npm run check
cargo test --locked --manifest-path packages/endpoint-agent/Cargo.toml
python3 -m unittest discover -s workers/integrity
python3 -m unittest discover -s workers/forensics
python3 -m unittest discover -s workers/imports
```
Confirme visibility=PRIVATE antes de usar o remoto. Não coloque tokens na URL.
A [documentação GitHub CLI](https://cli.github.com/manual/gh_repo_view) descreve
a consulta do repositório autenticado.

## Instalar e abrir o Codex

A documentação oficial consultada em25/10/2026 oferece instalador standalone
para Linux. Para manter uma etapa de inspeção, baixe antes de executar:
```bash
curl -fsSL https://chatgpt.com/codex/install.sh -o /tmp/codex-install.sh
less /tmp/codex-install.sh
sh /tmp/codex-install.sh
codex
```
O último comando deve ser executado na raiz do repositório. Na primeira execução,
use a opção de entrada com ChatGPT disponível na sua conta. Confira eventuais
mudanças nas [instruções oficiais do Codex CLI](https://learn.chatgpt.com/docs/codex/cli).
Este documento não instala Codex nem altera sua assinatura.

Para conferir a sessão:
```bash
codex login status
```
Não copie credenciais para o Git. O arquivo de autenticação, quando utilizado,
contém tokens; prefira autenticar novamente no Debian. Consulte
[autenticação oficial](https://learn.chatgpt.com/docs/auth).

AGENTS.md é carregado como orientação do repositório; PROJECT_STATE.md guarda
o ponto real de retomada. Isso permite continuar sem acesso a esta conversa,
conforme o mecanismo oficial de
[instruções de projeto](https://learn.chatgpt.com/docs/agent-configuration/agents-md).
Na nova sessão, escreva: “Leia AGENTS.md e PROJECT_STATE.md e continue da próxima
tarefa registrada, sem revisão ampla dos componentes já verificados.”

VS Code é opcional: abra a pasta clonada e use a integração oficial disponível
para sua instalação, ou continue pelo terminal Codex. Não há dependência do editor.

## Homologar a instância no Debian

Depois dos testes locais, configurar PostgreSQL dedicado, identidades mínimas,
chave sob custódia, permissões600 para credenciais, TLS quando remoto e serviço
systemd conforme o exemplo. Testar restauração em banco novo e os adaptadores
do SO. Nmap, Kali/KVM e rede de laboratório precisam de avaliação própria.
Não promover módulos a M4 com base apenas no sucesso dos testes Windows/Ubuntu.

## Voltar ao Windows

No Debian, registrar estado, testar, verificar segredos, commit e push da branch.
No Windows, preservar alterações locais antes de:
```powershell
git status
git pull --ff-only
.\scripts\doctor.ps1
.\scripts\setup-windows.ps1
npm run check
```
Reconstruir dependências e binários no Windows. Se as branches divergirem,
resolver explicitamente; não usar reset --hard nem push --force para ocultar
a divergência.
