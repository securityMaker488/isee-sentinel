# I.See Sentinel — instruções do repositório

Produto proprietário da I.See Technologies, Private Operator Edition. Fundador
único; clientes são organizações/projetos, não usuários públicos. Priorizar
funcionalidades locais e verificáveis, sem SaaS, Docker ou APIs pagas obrigatórias.

## Retomada

Ao receber “continue”, ler primeiro PROJECT_STATE.md e o trecho relevante do
ROADMAP.md. Retomar a próxima tarefa registrada, sem repetir auditoria ampla ou
reler todos os prompts. Corrigir erros encontrados no escopo. Inspecionar arquivos
novos/alterados e dependências necessárias antes de editar. Não pular fases nem
marcar implantação Debian como concluída por testes no Windows.

Guia único de requisitos: docs/GUIA-MESTRE-CONSOLIDADO.md. Ele reúne V5.0,
V6.3, V6.5, V6.6, V6.9, V11.0 e os dois complementos, com conflitos resolvidos.
V11 rege os marcos0–5; as fases antigas preservam cobertura, sem fila paralela.
Consultar só suas seções pertinentes à tarefa; originais e hashes ficam em
docs/PROMPT-COVERAGE.json e docs/PROMPTS-REGISTRY.md. Não abrir filas paralelas.
A matriz central é
PORTFOLIO_CAPABILITY_MATRIX.md, com dados em docs/portfolio-capabilities.json.
Preferências mais recentes do operador prevalecem sobre esses arquivos.
Complemento AttackLab de26/10/2026: docs/COMPLEMENTO-ATTACKLAB-EVIDENCE-FUSION.md.
Plano/auditoria: docs/ATTACKLAB-EVIDENCE-FUSION-PLAN.md. Suas seis fases detalham
o AttackLab dentro da V6.9; não reiniciar auditoria global nem assumir execução
Linux/isolamento já validado. O manifesto de IPv4/portas/exclusões foi integrado
na migração010; manter a exigência em qualquer executor novo. Descoberta não
equivale a vulnerabilidade confirmada. O plano AttackLab é histórico/complementar;
o próximo passo atual é determinado apenas por PROJECT_STATE.md e ROADMAP.md.

## Arquitetura e convenções

- apps/api: Fastify/TypeScript, consultas parametrizadas, PostgreSQL operacional;
  PGlite somente testes/desenvolvimento explícito. Migrações versionadas e
  checksums; não editar migração já entregue/aplicada em instalação real.
- apps/web: React/TypeScript/Vite/Tailwind, UI acessível em português. Dados
  pertencem à empresa em contexto; invalidar respostas antigas ao trocar contexto.
- packages/core: motores determinísticos, entradas limitadas, sem subprocessos,
  acesso ao disco/rede ou execução do conteúdo analisado.
- packages/endpoint-agent: Rust, consentimento, escopo, coleta explícita,
  autenticação de serviço. Nenhum shell remoto nem autopersistência silenciosa.
- packages/execution-engine: supervisor Rust opcional do worker confiável de
  arquivos; contrato estrito e recibos, sem sandbox geral. docs/RUST-ENGINES.md.
- workers: Python isolado, entradas explícitas, originais preservados e limites.
- Runtimes de referência: Node24, Python3.11+, Rust/Cargo com lockfile.
  Scripts e docs devem funcionar sem caminhos pessoais absolutos.

Reutilizar os componentes funcionais. Justificar novas dependências e verificar
licenças/versões de integrações. Ferramenta comercial citada é referência, não
licença de integração. Não declarar equivalência, proteção global ou maturidade
operacional sem evidência. Dados sintéticos devem ficar identificados.

## Segurança e Git

Preservar MFA, CSRF, isolamento por organização/ativo, autorização explícita,
credenciais cifradas, integridade e auditoria. Sem segredos em logs, prompts,
commits ou relatórios. Não incluir banco/chave/credencial/.env real no Git.
Executar a verificação de repositório antes de commit/push; ela não substitui
revisão dos arquivos. Não usar push --force, mudar remoto, tornar repositório
público ou publicar código sem autorização específica. O remoto desejado é
privado securityMaker488/isee-sentinel já foi criado e o push foi autorizado.
Conferir o remoto observado antes de sincronizar; preservar a privacidade.

Não formatar, particionar, mudar bootloader, apagar Windows, alterar serviços
preexistentes ou iniciar ação ofensiva fora de escopo. Instalação do SO é separada.
Correções de cópias de laboratório não equivalem a executar mudanças no host.

## Compilação e testes

No root: npm ci --ignore-scripts; npm run check; npm run inventory.
Agente: cargo test --locked --manifest-path packages/endpoint-agent/Cargo.toml.
Supervisor: cargo fmt/clippy/test/build conforme docs/RUST-ENGINES.md.
Testes reais exigem SENTINEL_TEST_EXECUTION_PATH e SENTINEL_TEST_PYTHON_PATH.
Python: python -m unittest discover -s workers/integrity e
python -m unittest discover -s workers/forensics.
Integração real do sensor: npm run verify:agent após compilar o binário.
Navegador: npm run qa:server e npm run qa:browser, somente banco sintético.
Use DEVELOPMENT.md para demais verificações e configuração opcional dos workers.

Executar testes relevantes, corrigir falhas e registrar o resultado real. Não
anunciar execução de CI, Debian, Nmap ou ferramentas externas sem tê-la realizado.
Ao encerrar, atualizar PROJECT_STATE.md, VALIDATION_REPORT.md e matriz conforme
o que mudou; registrar serviços temporários ativos e o próximo passo concreto.
