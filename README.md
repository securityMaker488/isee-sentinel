# I.See Sentinel · Private Operator Edition 0.2
aqui e as ordens pra nao se esquecer e usar 

Implementação incremental conforme diretriz **V11.0**, preservando requisitos anteriores, com um único
operador fundador e empresas/projetos separados. O núcleo conecta análise,
evidências, detecção, investigação e relatórios. O agente Rust possui envio
autenticado e monitoramento limitado de arquivos; SecureFix mantém correções
reversíveis sobre cópias de laboratório. A matriz funcional descreve cada recorte.

Não é uma plataforma enterprise concluída. As capacidades futuras e os limites
estão em `PORTFOLIO_CAPABILITY_MATRIX.md` e `ROADMAP.md`; nenhuma certificação ou validação independente é
alegada. Arquivos do laboratório são sintéticos e identificados como tal.

## Iniciar localmente

Os requisitos das oito fontes estão no [guia mestre consolidado](docs/GUIA-MESTRE-CONSOLIDADO.md).
Para retomar, use [PROJECT_STATE.md](PROJECT_STATE.md) e a fila única do ROADMAP.
O manifesto de alvos inclui IPs, portas e exclusões na aprovação do inventário.
Estado real: [MODULE_STATUS.md](MODULE_STATUS.md). Resultados Windows:
[VALIDATION_REPORT.md](VALIDATION_REPORT.md). O Universal Import Lab inspeciona ZIP/TAR/TAR.GZ
em quarentena; [IMPORT_PIPELINE.md](IMPORT_PIPELINE.md) descreve os limites.
Perícia offline e importação exigem Python local configurado no servidor.
A importação pode usar o [supervisor Rust](docs/RUST-ENGINES.md), com recibos
de integridade e cancelamento após revogação/expiração detectada.

A tela **Autorizações** registra responsável, comprovação cifrada, projeto,
ativos e limites. A aprovação explícita habilita perfis definidos; revogar não
restaura permissões antigas. Consulte [AUTHORIZATION_POLICY.md](AUTHORIZATION_POLICY.md).
A tela **Avaliações** mantém planos e revisões ligados à autorização aprovada.
A análise estática e a inspeção de arquivos podem ser executadas por etapa, preservando o vínculo com o job
e as evidências; os demais perfis indicam seu estado de integração.
Consulte [planos de avaliação](docs/ASSESSMENT-PLANS.md).
Código e memória de continuidade são sincronizados no
[repositório privado](https://github.com/securityMaker488/isee-sentinel).
As pendências Windows continuam registradas; o preparo do GitHub não encerra
essa etapa nem homologa o Debian.

Requer Node.js 24 LTS, npm e PostgreSQL local dedicado. Não exige Docker, Podman,
nuvem, GPU, Firebase, Supabase ou serviço externo. Prepare as identidades do banco
conforme `docs/OPERACAO.md` e defina `DATABASE_URL` no ambiente.

```sh
npm ci --ignore-scripts
npm run build
npm run bootstrap
# Após bootstrap, use a identidade de serviço em DATABASE_URL antes de iniciar.
npm start
```

Abra **http://127.0.0.1:4310**. O bootstrap pergunta e-mail e organização, cria
uma senha aleatória e exibe o segredo/URI TOTP uma única vez. Guarde a senha em
um gerenciador e cadastre o segredo em um autenticador antes de entrar. Não há
conta padrão, senha embutida, modo de autenticação simulada ou bypass de MFA.
Não execute bootstrap com saída redirecionada a logs. Ele também exibe um código
de recuperação de uso único; guarde-o offline e separado das demais credenciais.
Não há criação de outros operadores. Para recuperar o fundador, pare o servidor
e use `npm run operator:recover`; a operação exige o código, rotaciona senha/MFA,
revoga sessões e gera um novo código. Bancos da V5 devem usar `operator:adopt`
com senha e TOTP do fundador existente antes de servir a edição privada.

O banco principal é PostgreSQL nativo local; sem `DATABASE_URL`, a inicialização
falha explicitamente. PGlite fica disponível somente para testes ou desenvolvimento
isolado com `SENTINEL_DATABASE_MODE=embedded`, persistido em `.sentinel/database`
e limitado a um processo. A chave que protege TOTP e evidências fica separada em
`.sentinel/master.key`. Preserve o banco e a chave em backups protegidos; perder
a chave impede recuperar esses dados. A inicialização do serviço verifica as
migrações e não executa DDL. Rode `npm run db:migrate` com a identidade de migração
ao atualizar. Não reutilize bancos de outros projetos.
As variáveis são lidas do ambiente; `.env.example` documenta as opções.

## Primeiro fluxo verificável

1. Entre com senha e código TOTP.
2. Em Assets, cadastre um ativo de laboratório.
3. Como administrador, conceda autorização para `scan`, com referência real do
   escopo autorizado e prazo de até 31 dias.
4. Em SecureBuild, selecione o ativo e envie `fixtures/lab/sshd_config` e
   `fixtures/lab/config.json`. São configurações deliberadamente inseguras e
   não devem ser instaladas em nenhum serviço.
5. Examine os achados, controles avaliados, hashes e o relatório JSON.
6. Em EvidenceChain, verifique a integridade dos originais. Em Audit, veja as
   operações e a sequência de custódia.
7. Conceda também `event.ingest` ao ativo de laboratório. No SOC, execute o cenário
   de cinco falhas sintéticas e examine o alerta persistido e o incidente vinculado.
   O resultado não representa uma invasão real.

O scanner aceita até 40 arquivos de texto, 256 KiB por arquivo e 1 MiB total.
Não executa conteúdo, instala dependências do projeto, abre URLs, percorre o
filesystem do servidor nem extrai arquivos compactados. Evidências binárias de
até 1 MiB são preservadas cifradas, sem execução ou renderização inline.

## Verificação

As novas telas são Endpoint Agent, Investigar e corrigir, Análises especializadas,
AttackLab e Matriz de capacidades. Consulte `docs/ANALISES.md`,
`docs/OPERACOES-DEFESA.md`, `docs/ATTACKLAB.md` e
`packages/endpoint-agent/README.md` para formatos e limites.

O monitoramento exige cadastro do agente, credencial local protegida e autorização
`event.ingest`. A primeira coleta não vira referência automaticamente: aprove o
hash após verificar sua origem. O servidor compara coletas futuras e abre um
incidente quando divergem. O sensor não é EDR completo.

Análises especializadas exigem `scan` e `evidence.import`. Elas aceitam somente os
formatos documentados. SecureFix exige ativo de laboratório e modifica somente
o artefato cifrado; não reinicia SSH nem altera o host. AttackLab requer Nmap
externo configurado e alvo de laboratório autorizado; a ferramenta não é incluída.

```sh
npm run check
npm audit
npm run inventory
```

Os testes de integração usam banco isolado em memória e dados sintéticos. O
resultado desta alteração fica em `VALIDATION_REPORT.md`; o histórico está em `docs/VALIDATION.md`.
O contrato OpenAPI está em `/api/openapi.json` após autenticação.

Para reproduzir o teste de navegador, rode `npm run qa:server` em um terminal e
`npm run qa:browser` em outro, após o build. O servidor de QA usa dados sintéticos
em memória na porta 4311 e autenticação real. Instale o navegador de teste com
`npx playwright install chromium` ou defina `SENTINEL_BROWSER_PATH` para um
executável compatível já instalado. As credenciais descartáveis e os resultados
ficam em `.sentinel/qa`, fora do controle de versão. Encerre o servidor ao terminar.

## Restrições operacionais

- O servidor escuta somente em loopback. HTTP é aceito apenas para origem local;
  acesso remoto exige HTTPS e configuração controlada de rede e proxy.
- TOTP é obrigatório; passkeys e rotação assistida
  de chaves ainda não estão disponíveis. Provisionamento é uma ação local
  privilegiada, auditada, para o responsável pelo host.
- Isolamento organizacional é aplicado no backend e nas chaves estrangeiras.
  Há identidades de agente e papéis distintos de banco; RLS e validação operacional
  ampliada com múltiplos clientes ainda estão pendentes.
- Barreiras refletem somente configurações enviadas, sem comprovar controles
  ativos em servidores. Não há percentual de proteção ou cobertura presumida.
- Jobs são persistidos, com executor síncrono limitado. Quedas deixam registro
  de interrupção na próxima inicialização; não há fila distribuída ou replay.
- Evidência e auditoria têm bloqueio de alteração por trigger. Um administrador
  do banco/host pode contorná-lo; não equivale a WORM ou custódia certificada.
- Autodefesa no host, implantação, recuperação de serviços, exploração ofensiva,
  agentes privilegiados e modelos de IA não têm executores habilitados. A correção
  de cópia e o inventário Nmap delimitado não equivalem a essas capacidades.
- As listagens mostram até 100 registros recentes; exportação integral e
  paginação serão necessárias para volumes maiores.

O desenvolvimento e os testes locais foram feitos no Windows disponível,
inclusive PostgreSQL nativo. Debian 13 KDE é o alvo principal; sua instalação,
dual boot, drivers, Podman e Kali/KVM ainda não foram executados. Consulte o
diagnóstico e execute `bash scripts/diagnose-linux.sh` no Linux de destino.
