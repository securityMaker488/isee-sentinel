# Operação local e homologação Linux

Esta versão permite desenvolvimento privado local. V6.5 adota PostgreSQL instalado e administrado localmente como banco principal. O exemplo systemd é um artefato para homologação; não foi instalado, habilitado ou testado em Linux nesta sessão. Não exige Firebase, Supabase, Docker, Podman, Redis, Kubernetes ou cloud paga.

## Inicialização local

Na raiz do repositório, com Node 24 LTS atualizado e npm disponíveis, prepare um PostgreSQL local dedicado e configure `DATABASE_URL` no ambiente privado do processo. Não use o banco existente de outra aplicação. O modo padrão `postgres` exige essa configuração; ausência da URL deve impedir inicialização. O administrador pode usar `ops/provision-postgres.sql`, que cria banco/papéis novos, pergunta senhas via `psql` e falha se os nomes já existirem. Esse arquivo é um modelo de provisionamento manual, não foi aplicado ao serviço PostgreSQL que já existia no computador. Depois:

```sh
npm ci --ignore-scripts
npm run bootstrap
npm run build
# Aplique ops/runtime-grants.sql como migrator e use DATABASE_URL do runtime.
npm start
```

O bootstrap é interativo e deve ocorrer em terminal privado. Ele recebe organização/e-mail e apresenta senha gerada e provisionamento TOTP. Registre o autenticador e guarde as credenciais com segurança. Não redirecione sua saída para logs, não cole o segredo no chat e não use conta demonstrativa compartilhada. Acesse `http://127.0.0.1:4310` após iniciar. A edição V6.3 aceita um único operador fundador; o provisionamento de outros usuários fica desabilitado. Organizações e projetos representam trabalhos do fundador, sem acesso de clientes ao painel.

`npm ci --ignore-scripts` instala exatamente o lockfile sem scripts de lifecycle. A instalação inicial precisa de registro npm acessível ou cache confiável. Depois, a execução básica é local. Não há chamada automática a provedor LLM.

| Variável | Comportamento |
|---|---|
| `SENTINEL_ORIGIN` | Origem pública exata; padrão `http://127.0.0.1:4310` |
| `SENTINEL_PORT` | Porta; padrão `4310` |
| `SENTINEL_DATA_DIR` | Diretório privado de dados; padrão `.sentinel` |
| `SENTINEL_DATABASE_MODE` | Padrão `postgres`; `embedded` apenas para desenvolvimento/testes explícitos |
| `DATABASE_URL` | Obrigatória no modo `postgres`: PostgreSQL local dedicado indicado pela URL |
| `SENTINEL_MASTER_KEY` | Opcional: 64 caracteres hexadecimais, 32 bytes. Alternativa local: arquivo `master.key` no diretório de dados |
| `SENTINEL_SECURE_COOKIE` | Configuração de cookie; HTTPS exige Secure |

As variáveis são lidas do ambiente do processo. O arquivo `.env.example` documenta o formato; não é um segredo e não é carregado automaticamente por `npm start`. Para um `.env` privado, o Node suporta iniciar com `node --env-file=.env --import tsx apps/api/src/server.ts`. Não coloque chave ou senha no repositório.

Somente para desenvolvimento sem servidor, defina `SENTINEL_DATABASE_MODE=embedded` explicitamente no ambiente de bootstrap e execução. Em PowerShell: `$env:SENTINEL_DATABASE_MODE='embedded'`; em Bash: `export SENTINEL_DATABASE_MODE=embedded`. Não deixe essa opção no perfil operacional PostgreSQL. PGlite deve ter um único processo usando seu diretório; pare o servidor antes de CLI e cópias a frio. Não execute migrações ou testes contra banco de cliente. As migrações versionadas ficam em `apps/api/migrations/`; mantenha seus checksums.

## Recuperação do fundador e atualização da edição

O bootstrap V6.3+ também gera um código de recuperação aleatório. Guarde-o offline separado de senha, autenticador e banco. `npm run operator:recover`, em terminal privado e com servidor parado, solicita o código sem eco, troca senha/TOTP, revoga sessões e gera outro código. O anterior é consumido transacionalmente. Recuperação precisa da chave mestra original e acesso autorizado ao banco; não recupera evidências se a chave foi perdida. Não existe reset público ou credencial padrão.

Ao migrar uma base V5 já inicializada, `npm run operator:adopt` seleciona o fundador existente mediante senha e TOTP. Demais contas deixam de ser aceitas no login da edição privada; a seleção revoga sessões e emite código offline. Faça backup e homologação em cópia antes da base operacional. Não remova dados ou apague banco para forçar bootstrap.

## Primeiro fluxo de operador

1. Entre com a senha e o TOTP recém-gerado; sem MFA válido não deve haver sessão.
2. Cadastre um ativo de laboratório e declare criticidade e ambiente corretos.
3. Como administrador, registre autorização com referência, operações permitidas e início/fim. Ela é uma declaração operacional, não um contrato verificado pelo aplicativo.
4. Envie apenas arquivos autorizados para SecureBuild. O backend limita a requisição a 3 MiB, o pacote a 40 arquivos/1 MiB total e cada arquivo a 256 KiB; a evidência individual tem limite de 1 MiB. Limites menores do backend prevalecem sobre o core.
5. Compare achados com a fonte enviada, veja evidências e calcule/verifique integridade. O scanner não executa scripts, instala dependências nem busca URLs.
6. Para correlação, eventos `auth.failure` podem gerar alerta persistido e incidente ao atingir 5 ocorrências em 5 minutos de recepção. Fonte, sujeito e marcação sintética são segregados; eventos sintéticos precisam permanecer identificados e exigem ativo de laboratório. ID externo permite deduplicação; mesmo ID com payload diferente deve falhar. Triagem de falso positivo é auditada.
7. Saia e confira que a sessão antiga deixa de funcionar. Registre falhas e resultados reais da operação.

As regras estáticas cobrem desabilitar verificação TLS, login SSH root por senha/configuração permissiva, CORS com origem universal e credenciais, marcadores PEM privados e indicadores de credenciais AWS. Arquivos `.env`, JSON e `sshd_config` suportados não reproduzem toda a resolução de configuração efetiva; configuração boa em um arquivo não prova a postura do host.

## Debian 13 Stable + KDE e compatibilidade Ubuntu LTS

Comece sem privilégios elevados:

```sh
bash scripts/diagnose-linux.sh
```

O script lê distribuição, kernel, CPU, memória, GPU, armazenamento agregado, virtualização e versões; não instala pacotes, altera serviços, lê variáveis secretas, varre rede ou modifica partições. Não deduza que KVM funciona apenas por flags da CPU. O diagnóstico precisa ser executado no Linux real; Git Bash não equivale a Debian.

Prepare Node 24 LTS, npm, Git, Python, Rust/Cargo e PostgreSQL suportado usando canais oficiais escolhidos pelo administrador. O pacote Node do Debian trixie consultado pertence à linha 20 e não atende este projeto; adote runtime 24 oficial verificado em diretório dedicado e configure caminho explícito, sem misturar repositórios de distribuições. Rust e Python são base para módulos futuros, não obrigação do servidor TypeScript inicial. Em Ubuntu, confira a versão da LTS antes de adotar. Não copie comandos de `initdb` sobre diretório existente. [Pacote Node trixie](https://packages.debian.org/trixie/nodejs), [Guia oficial Ubuntu PostgreSQL](https://ubuntu.com/server/docs/how-to/databases/install-postgresql/) e [política de versões PostgreSQL](https://www.postgresql.org/support/versioning/).

Para serviço: use usuário Linux dedicado `isee-sentinel`, sem login interativo ou sudo; código em `/opt/isee-sentinel` somente leitura; dados em `/var/lib/isee-sentinel` privados; configuração em `/etc/isee-sentinel/sentinel.env` restrita ao administrador. Prepare banco exclusivo e duas identidades PostgreSQL: proprietário/migração e runtime limitado. Bootstrap e `npm run db:migrate` usam credencial de migração; o servidor apenas verifica o esquema/checksums e não executa DDL automaticamente. Após migrar, aplique os privilégios revisados em `ops/runtime-grants.sql` com a identidade autorizada e inicie o servidor com a credencial runtime. Não conceda superuser, criação de papéis ou propriedade de tabelas ao runtime. Valide os grants na instância isolada antes da base operacional; sucesso no Windows não homologa o serviço Debian.

`ops/isee-sentinel.service.example` contém um exemplo de unidade com `NoNewPrivileges`, capabilities vazias, proteção do sistema de arquivos e limites de recursos. O caminho `/opt/node24/bin/node` é uma convenção a adaptar ao runtime realmente instalado; não existe por efeito deste arquivo. Ajuste caminhos e orçamento ao diagnóstico. Não habilite `MemoryDenyWriteExecute` indiscriminadamente: V8/WASM usam memória executável. Verifique `systemd-analyze verify` e `systemd-analyze security` no host, depois teste operação e restore. A pontuação dessas ferramentas não é certificação. As diretivas seguem a [documentação systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

O exemplo mantém loopback. Acesso remoto futuro requer VPN/túnel autenticado ou proxy TLS privado, revisão de origin/cookies, firewall e logs. Não publicar a central administrativa na internet.

## Backup e restauração

Defina RPO/RTO com o responsável pelos dados; não há valor garantido. Guarde banco, metadados, versão do aplicativo/migração e chave em meios protegidos. A chave deve ter custódia separada; uma cópia do banco sem a chave não recupera evidências cifradas, e uma chave no mesmo backup amplia o impacto de vazamento.

Para PGlite, encerre o processo de forma limpa, confira que não há outro processo usando o diretório e copie o diretório completo para destino novo protegido. Não faça cópia parcial de banco aberto. Teste a cópia em diretório novo e porta diferente, preservando o original. A recuperação por cópia a frio neste modo precisa de homologação própria.

Para PostgreSQL dedicado, use `pg_dump` compatível com a versão e restaure em banco novo de teste. Exemplo para administrador que já configurou aliases privados `pg_service.conf` e credenciais seguras:

```sh
pg_dump --dbname=service=sentinel_source --format=custom --file=sentinel-backup.dump
pg_restore --dbname=service=sentinel_restore_test --no-owner --no-privileges --exit-on-error sentinel-backup.dump
```

`sentinel_restore_test` deve apontar para banco vazio separado, nunca produção. O exemplo não usa `--clean` ou exclusão. Restrinja o arquivo de backup e registre SHA-256, tamanho, data, duração e resultado. Após restaurar, inicie cópia isolada da aplicação com a mesma chave sob custódia autorizada e confirme login/MFA, contagens por organização, hashes de evidência e cadeia de auditoria. Uma saída zero de `pg_dump` sozinha não é teste de restauração.

Durante incidente, preserve evidências antes de contenção/recuperação. Não apague banco ou arquivos para desbloquear bootstrap; erro de migração exige diagnóstico e cópia segura. Rotação automatizada da chave não está implementada: não substitua `master.key` sem migração dos dados cifrados e teste de recuperação.

## Verificação e manutenção

`npm run check` executa build e testes disponíveis. `npm run inventory` gera o inventário das dependências instaladas; `npm audit` consulta advisories e exige acesso ao registro. Revise o diff do lockfile e as licenças antes de atualizar. Não execute `npm audit fix --force` como rotina. Dependências sem alerta conhecido ainda podem conter falhas.

Monitore saúde, espaço livre e falhas do processo no host; o Sentinel ainda não oferece supervisão externa ou SLA. Em systemd, o journal pode conter dados operacionais: aplique retenção e acesso mínimo. Para manutenção que envolva PGlite, pare o processo antes de copiar ou operar a CLI. Nunca trate o exemplo de unidade como instalação concluída.
