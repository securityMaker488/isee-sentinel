# Preparação e implantação privada

O perfil operacional é PostgreSQL local dedicado e Command Center em loopback.
A homologação Debian 13 permanece separada dos testes Windows. Este guia não
instala sistema operacional, particiona discos ou modifica serviços existentes.
Procedimento detalhado: [docs/OPERACAO.md](docs/OPERACAO.md).

## Preparar código e ferramentas

Requisitos de referência: Node 24/npm, Git, Python 3.11+ para workers e Rust/Cargo
1.98.1 para a toolchain verificada no desenvolvimento. O doctor usa esse piso
conservador de Rust; a declaração de MSRV de uma crate não comprova todos os
alvos/dependências com versões anteriores.

Windows, na raiz do repositório:

```powershell
.\scripts\doctor.ps1
.\scripts\setup-windows.ps1
```

Debian já instalado e autorizado:

```bash
bash scripts/doctor.sh
bash scripts/setup-debian.sh
```

Setup instala dependências do lockfile sem lifecycle scripts npm, compila web e
agente e executa diagnóstico. Não provisiona banco, fundador ou serviço. Testes
podem ser incluídos com `-RunTests` no PowerShell ou `--test` no Bash; veja
[TESTING.md](TESTING.md). Não transporte `node_modules`, `target` ou ambientes
Python entre sistemas.

## Banco, chave e primeiro operador

1. Preparar banco exclusivo e identidades diferentes para migração e runtime.
   [ops/provision-postgres.sql](ops/provision-postgres.sql) é um modelo manual;
   revise nomes e confirme que o destino é novo antes de executá-lo.
2. Definir `DATABASE_URL` da identidade migradora no ambiente privado e escolher
   um diretório de dados protegido. O modo padrão exige PostgreSQL; não muda
   silenciosamente para banco embarcado.
3. Executar `npm run bootstrap` em terminal privado. O comando aplica migrações,
   cria o único fundador e exibe senha, TOTP e recuperação uma vez. Não gravar
   essa saída em logs. Guardar a chave mestra e recuperação sob custódia separada.
4. Aplicar os privilégios revisados de
   [ops/runtime-grants.sql](ops/runtime-grants.sql) e trocar o ambiente do servidor
   para a identidade runtime, sem poderes de administração do banco.
5. Executar `npm start` e acessar `http://127.0.0.1:4310`. Validar login/MFA,
   projeto/ativo/escopo, evidência, logs e recuperação em ambiente próprio.

Instância existente: preservar banco/chave/configuração/versão antes de migrar;
executar `npm run db:migrate` com a identidade de migração, reaplicar grants
necessários e iniciar com runtime. O servidor verifica checksums e não aplica DDL
no startup. Não editar migrações já aplicadas para contornar erro de checksum.

## Configuração e adaptadores

[.env.example](.env.example) documenta variáveis sem segredos. Elas são lidas do
processo; `.env` não é carregado automaticamente por `npm start`. Para um arquivo
local protegido, o comando suportado é:

```text
node --env-file=.env --import tsx apps/api/src/server.ts
```

- `SENTINEL_PYTHON_PATH`: caminho absoluto ao Python confiável para perícia e
  inspeção ZIP. Configuração presente não prova execução do worker.
- `SENTINEL_NMAP_PATH`: caminho absoluto ao Nmap instalado separadamente.
  Disponibilidade, versão, licença e autorização precisam de verificação própria.
- `SENTINEL_ORIGIN`/`SENTINEL_PORT`: origem/porta esperadas. Acesso remoto exige
  TLS e desenho de acesso privado; não publicar o painel administrativo por padrão.
- `SENTINEL_MASTER_KEY` ou `master.key`: segredo necessário para ler dados
  cifrados. Substituí-lo sem migração criptográfica torna os dados inacessíveis.

Workers executados como processos limitados não equivalem a VMs de isolamento.
O importador ZIP não extrai nem executa aplicações; o adaptador Nmap não instala
Kali nem cria rede isolada.

## Serviço, atualização e recuperação

[ops/isee-sentinel.service.example](ops/isee-sentinel.service.example) é um
exemplo systemd a adaptar e validar no Debian real. Use conta sem privilégios,
código protegido, dados privados e orçamento de recursos. Não há instalação
automática de serviço Windows ou política de persistência do agente.

Antes de atualizar, testar em cópia dedicada: migrações, grants, inicialização,
fluxos relevantes e restauração. Rollback de banco exige estratégia compatível;
trocar apenas o código não desfaz necessariamente migrações. Procedimento e
limitações em [BACKUP_RECOVERY.md](BACKUP_RECOVERY.md).

Não há desinstalador automático completo. Encerrar os processos/serviços criados
especificamente para esta instância, preservar dados/chave conforme retenção e
planejar a remoção explícita de seus próprios arquivos. Não excluir diretórios
de outros serviços, bancos ou ferramentas compartilhadas.

Continuidade entre sistemas: [MIGRATION-DEBIAN.md](MIGRATION-DEBIAN.md).
Nenhum resultado de CI ou teste local substitui implantação/homologação real.
