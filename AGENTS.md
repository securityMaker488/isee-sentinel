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

Fontes vigentes: docs/ESPECIFICACAO-V6.9.txt e o complemento
docs/COMPLEMENTO-MULTIPLATAFORMA.txt. A matriz central é
PORTFOLIO_CAPABILITY_MATRIX.md, com dados em docs/portfolio-capabilities.json.
Preferências mais recentes do operador prevalecem sobre esses arquivos.
Complemento AttackLab de26/10/2026: docs/COMPLEMENTO-ATTACKLAB-EVIDENCE-FUSION.md.
Plano/auditoria: docs/ATTACKLAB-EVIDENCE-FUSION-PLAN.md. Suas seis fases detalham
o AttackLab dentro da V6.9; não reiniciar auditoria global nem assumir execução
Linux/isolamento já validado. Vincular alvos e exclusões ao pedido aprovado antes
de ampliar executores ativos. Descoberta não equivale a vulnerabilidade confirmada.

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
privado e se chama isee-sentinel; não presumir que já existe.

Não formatar, particionar, mudar bootloader, apagar Windows, alterar serviços
preexistentes ou iniciar ação ofensiva fora de escopo. Instalação do SO é separada.
Correções de cópias de laboratório não equivalem a executar mudanças no host.

## Compilação e testes

No root: npm ci --ignore-scripts; npm run check; npm run inventory.
Agente: cargo test --locked --manifest-path packages/endpoint-agent/Cargo.toml.
Python: python -m unittest discover -s workers/integrity e
python -m unittest discover -s workers/forensics.
Integração real do sensor: npm run verify:agent após compilar o binário.
Navegador: npm run qa:server e npm run qa:browser, somente banco sintético.
Use DEVELOPMENT.md para demais verificações e configuração opcional dos workers.

Executar testes relevantes, corrigir falhas e registrar o resultado real. Não
anunciar execução de CI, Debian, Nmap ou ferramentas externas sem tê-la realizado.
Ao encerrar, atualizar PROJECT_STATE.md, VALIDATION_REPORT.md e matriz conforme
o que mudou; registrar serviços temporários ativos e o próximo passo concreto.
