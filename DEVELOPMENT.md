# Desenvolvimento Windows e Debian

O projeto usa uma base de código com adaptadores por sistema. Requisitos:
Node.js24/npm, Git, Python3.11+ e Rust/Cargo; PostgreSQL dedicado para operação.
Testes JS usam banco isolado em memória. Docker, Kali e serviços pagos não são requisitos.

## Preparar ferramentas e compilar

Instale ferramentas ausentes pelos canais oficiais indicados pelo doctor.
Os scripts de setup preparam dependências locais; não instalam o sistema,
não criam banco operacional e não alteram serviços existentes.

Windows (PowerShell, na raiz):
```powershell
.\scripts\doctor.ps1
.\scripts\setup-windows.ps1
npm run check
cargo test --locked --manifest-path packages/endpoint-agent/Cargo.toml
python -m unittest discover -s workers/integrity
python -m unittest discover -s workers/forensics
```

Debian/Linux:
```bash
bash scripts/doctor.sh
bash scripts/setup-debian.sh
npm run check
cargo test --locked --manifest-path packages/endpoint-agent/Cargo.toml
python3 -m unittest discover -s workers/integrity
python3 -m unittest discover -s workers/forensics
```

Não copie node_modules, target, binários compilados ou .venv entre sistemas.
Use npm ci e Cargo.lock. Para dependências, prefira atualizar em branch,
revisar alterações de lockfile e executar verificações antes de integrar.

## Executar com dados sintéticos

Após build:
```text
npm run qa:server
```
Em outro terminal:
```text
npm run qa:browser
```
O servidor de QA usa porta4311 e dados temporários. Credenciais e resultados
ficam em .sentinel/qa, ignorado pelo Git. Encerre-o após o teste.
Para validar o sensor compilado: npm run verify:agent. Não é um teste no Debian.

## Instância privada operacional

Siga docs/OPERACAO.md: banco dedicado, papel migrador, papel runtime e chave
separada. Defina DATABASE_URL por ambiente protegido, execute bootstrap/migrações
com a identidade adequada, aplique ops/runtime-grants.sql e inicie com runtime.
Nunca use a identidade de outros serviços. O servidor padrão escuta127.0.0.1:4310.
As opções estão em .env.example; nenhum script imprime segredos.

Worker forense opcional: SENTINEL_PYTHON_PATH deve apontar ao Python absoluto
da máquina atual. Nmap opcional: SENTINEL_NMAP_PATH aponta ao executável oficial
instalado/licenciado. Configuração de caminho não comprova instalação nem execução.
O core não precisa desses adaptadores para inicializar.

## Trabalho por branches

Antes de editar, leia AGENTS.md e PROJECT_STATE.md:
```text
git status
git pull --ff-only
git switch -c feat/descricao-curta
```
Use pull somente com remoto configurado e alterações locais preservadas.
Não sobrescreva trabalho não sincronizado. No final:
```text
npm run check
npm run verify:repository
git diff
git add CAMINHOS_REVISADOS
git diff --cached
npm run verify:repository
git commit -m "feat: descreve comportamento verificado"
git push -u origin NOME_DA_BRANCH
```
Os nomes em maiúsculas são substituições conscientes. Push somente ao repositório
privado conferido e autorizado. Não use force-push. Conflitos exigem preservar
os dois conjuntos de alterações, resolver e testar; não descarte arquivos para
“sincronizar”. [Comportamento oficial de git pull](https://git-scm.com/docs/git-pull).

CI foi preparada para Windows e Ubuntu; resultado de runner não substitui
homologação Debian13. Estado de execução está em VALIDATION_REPORT.md.
