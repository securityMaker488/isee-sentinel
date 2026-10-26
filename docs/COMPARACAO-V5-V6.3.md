# Comparação V5.0 → V6.3 → V6.5

V6.5 é a especificação vigente. O nome do arquivo preserva a primeira comparação e esta revisão acrescenta os deltas posteriores. A fundação iniciada a partir de V5.0 é preservada e adaptada por mudanças rastreáveis. Não há reinicialização do projeto, remoção de segurança por existir apenas um operador ou instalação do sistema operacional.

| Delta V6.3 → V6.5 | Decisão vigente | Evidência / limite |
|---|---|---|
| Arquitetura híbrida | A: Debian nativo; B: Podman rootless opcional; C: Kali QEMU/KVM | Planejada em `FASES-V6.5.md`; não instalada |
| Banco principal | PostgreSQL local administrado obrigatório no modo padrão | `DATABASE_URL` explícita; PGlite somente modo `embedded` de desenvolvimento/teste |
| Firebase/Supabase | Exclusivamente tecnologias externas auditáveis | Nenhum backend, serviço ou adaptador interno instalado; fase 8 futura |
| Hardware externo | HD externo de 1 TB declarado | Não montado/formatado; capacidade não medida nesta sessão |
| Formação | 21 tópicos, incluindo Terminal/Bash, Podman e KVM | Curso reorganizado; aula 1 continua fundamento |
| Fases |0–10 com gates | Fase 0 pendente no Debian; entregas Windows preparatórias preservadas |
| Rust/Python | Protótipo offline de observação/validação de arquivo | Testes Windows; sem ingestão de agente nem serviço residente |

| Tema | V5.0 | V6.3 / decisão atual | Estado |
|---|---|---|---|
| Sistema principal | Arch Linux | Debian 13 Stable + KDE Plasma | Alvo documentado; migração não executada |
| Ambiente acessível | Não presumir Linux | Windows 10 observado, Debian futuro | Diagnóstico real preservado; nenhuma alegação de Debian validado |
| Operadores | Base interna com RBAC | Um fundador; clientes não acessam painel | CLI/backend/UI adaptados; unicidade, login restrito, recuperação e isolamento testados em `VALIDATION.md` |
| Organizações/projetos | Isolamento multiempresa futuro | Empresas/projetos privados do único fundador | Contexto de organização na sessão e filtro backend; sem SaaS |
| Stack | TypeScript e Python | TypeScript/Python e agentes Rust | Backend/React preservados; protótipo Rust offline e validador Python testados; integração de sensor futura |
| Detecção | DefenseFlow e incidentes | Detection Engine explícito, regra versionada e alerta persistido | Evolução da regra de 5 falhas/5 min; alerta sintético identificado |
| Endpoint Security | Hardening inicial | Agente próprio Linux/Windows com APIs nativas | Planejado; nenhum sensor instalado |
| IdentityGuard | Identidades dentro dos planos | Módulo dedicado AD/LDAP/cloud/MFA | Planejado, priorizar leitura |
| CloudShield | Segurança cloud como perspectiva | Módulo dedicado AWS/Azure/GCP/IaC | Planejado; sem credenciais ou custo externo |
| ExposureMap | Ativos/RiskGraph | Motor próprio de inventário e exposição | Planejado; cadastro de ativo não prova descoberta de exposição |
| Threat Hunting/Vulnerability Management | Capacidades distribuídas | Módulos explícitos | Planejado além de achados/eventos atuais |
| Validation Lab | Estratégia de testes | Laboratório de cobertura/FP/FN/agentes/recuperação | Suítes existentes são base; programa enterprise planejado |
| Hardware | Diagnosticar antes de instalar | SSD 480 GB e HD externo declarados | Volume C: 239 GB observado é dado separado; não inferir partições |
| Kali | VM isolada | QEMU/KVM+libvirt+virt-manager; hipótese de 2 vCPUs/4 GiB | Planejado; dimensionar após diagnóstico Debian |
| Comercial | Futuro produto/SaaS | Adiado expressamente; sem portal/cadastro/pagamentos | Nenhuma função comercial necessária à edição privada |
| Maturidade | Planejado → comercialização | M0–M6 com evidências | Escala adotada; nenhum módulo M4–M6 |
| Formação | Documentação técnica | Curso22 tópicos, do fundamento ao avançado | Trilha e aula 1 entregues; domínio do aluno ainda não avaliado |
| Barreiras/motores |14 camadas e motores originais | Preservados integralmente | Catálogo e fatias reais; demais capacidades planejadas |

## Maturidade

| Nível | Significado | Evidência mínima |
|---|---|---|
| M0 | Planejado | Requisito, fronteira e critério de aceite |
| M1 | Protótipo | Código executável isolado com limites declarados |
| M2 | Integrado | Contrato, persistência e fluxo de operador conectados |
| M3 | Testado | Casos executados e resultados, ambiente e versão registrados |
| M4 | Operacional internamente | Homologação Debian/serviço, recuperação, acesso, procedimentos e responsável |
| M5 | Preparado para avaliação comercial | Licenças/privacidade/suporte e capacidade avaliados |
| M6 | Enterprise validado | Avaliação independente e requisitos enterprise aceitos com evidência |

As fatias existentes só podem alcançar M3 no escopo dos testes executados. Uma alteração V6.3 exige reteste; não herda automaticamente resultados da implementação anterior. Os módulos planejados seguem M0, mesmo quando aparecem no inventário.

## Rastreabilidade das tarefas iniciais

| Etapa V5.0 | Entrega / evidência | Limite |
|---|---|---|
|1 Repositório | Monorepo npm apps/packages/docs/ops | Git remoto privado não provisionado automaticamente |
|2 Fundação | Fastify/React/TypeScript, lockfile e scripts | Deploy público não realizado |
|3 Autenticação/autorização | Argon2id/TOTP/sessão/CSRF/PolicyGate e recuperação CLI por código de uso único | WebAuthn, reautenticação sensível e homologação operacional pendentes |
|4 Banco | Migrações PostgreSQL e PGlite | Banco de cliente existente preservado |
|5 Command Center | UI conectada a dados reais | Não representa módulos planejados como operacionais |
|6 PolicyGate | Escopo por recurso/organização/operação/prazo | Sem executor arbitrário |
|7 Evidências | Bytes cifrados, SHA-256 e auditoria | Sem WORM/ancoragem externa |
|8 Eventos | Esquema v1, timestamps e origem | Origem declarada não é sensor autenticado |
|9 Primeira análise | SecureBuild config/indicadores de segredos | Não equivale a SAST/DAST amplo |
|10 Barreiras |14 camadas, avaliações estáticas explícitas | `runtimeVerified=false` |
|11 Testes | Suítes core/API | Sem certificação |
|12 Verificações | Execuções registradas no relatório final | Resultado anterior precisa reteste após mudanças |
|13 Correções | Ajustes de dependências/integração mediante falhas | Não há promessa de ausência de bugs |
|14 Documentação | Arquitetura, ADR, matriz, operação e fontes | Homologação Debian continua pendente |

Na V6.3, as etapas1–5 de auditar/configurar Debian só podem ser fechadas quando o Debian estiver disponível. As etapas6–12 de repositório/backend/frontend/banco/login/gate/eventos têm base implementada no Windows; etapas13–16 avançam com regra, alerta persistido sintético e UI;17–18 exigem teste atualizado e documentação. A existência de artefatos preparados não fecha a validação do sistema operacional.
