# Roadmap V6.9 — fases 0 a 12

Atualizado em 01/11/2026 sob o guia único `docs/GUIA-MESTRE-CONSOLIDADO.md`, conforme `docs/ESPECIFICACAO-V6.9.txt`, §46 e diretriz
final. Comparação em `docs/EVOLUCAO-V6.9.md`; resultados recentes e ponto de
retomada em `PROJECT_STATE.md`. Esta ordem não afirma que testes pendentes passaram.

Prioridade: **fundação segura → Universal Import Lab → Authorization Manager e
PolicyGate aplicados ao fluxo → ProofLab → auditoria Web/API → Remediation Engine
→ retestes e relatórios**. Autorização e evidências básicas são pré-requisitos da
importação, mesmo quando seu aperfeiçoamento continua nas fases seguintes.

Preservar recortes já implementados de fases posteriores. Não reiniciar o produto
nem bloquear desenvolvimento portátil porque Debian ainda não foi homologado.
Também não encerrar fases com dependências operacionais pendentes. A inspeção
parte do checkpoint e das interfaces afetadas, sem repetir revisões amplas.

## Fases e critérios de conclusão

| Fase | Escopo e base disponível | Próximo incremento / dependências | Evidência de conclusão do recorte |
| --- | --- | --- | --- |
| 0 — Auditoria | Inventário/arquitetura; OpenAPI/RiskGraph/perícia integrados, QA/restore e auditoria dirigida AttackLab registrados; prompts consolidados | Manter apenas revisão dirigida de novos requisitos/alterações e coerência documental | Resultados em VALIDATION_REPORT.md; não reiniciar revisão integral |
| 1 — Fundação | React/Fastify/PostgreSQL, MFA, clientes/projetos, PolicyGate, escopos e evidências; Authorization Manager com responsável, comprovação cifrada, revisão/aprovação, perfis e limites aplicados | Plano completo de avaliação/importação e contratos de execução geral; ampliar os perfis junto de cada executor, sem liberar ações ainda indisponíveis | Testes de identidade, isolamento organização/projeto, migrações, backup/restore e falhas; testes de aprovação, substituição/revogação, bytes e portas; homologação Debian registrada separadamente |
| 2 — Universal Import Lab | Uploads e análises específicas fornecem partes do fluxo | Preservar/identificar/quarentenar artefato próprio; expansão segura de ZIP/TAR, URL e Git por adaptadores separados | Limites, hashes, travessia, links, expansão, erros/limpeza e permissão testados; nenhuma execução automática de software desconhecido no host |
| 3 — ProofLab | SOC sintético e SecureFix de cópia reaproveitáveis | Aplicação vulnerável local, isolamento e cenário integrado à importação/avaliação | Importar → avaliar → evidência → corrigir cópia → retestar comparavelmente → relatar, identificado como laboratório; isolamento/recuperação testados |
| 4 — Security Assessment | Baseline, analisadores offline e OpenAPI JSON integrados | Web/API, catálogo de testes, SAST/SCA e DAST controlado por etapas; ferramentas/feeds com origem/versão/licença | Positivos/negativos, entradas malformadas, limites, evidências e relatório; ausência de achado não implica segurança |
| 5 — Remediation | Ciclo reversível de cópia SSH cifrada | Git, regressão, homologação, comparação e reteste vinculado ao achado; produção exige aprovação específica | Correção testada, risco residual, original/diff/aprovação, verificação e rollback; cópia no banco não equivale a alteração do host |
| 6 — Execution Center | APIs, jobs registrados e CLIs específicas | Fila PostgreSQL, prioridade, estados completos, cancelamento, retomada e CLI; antecipar apenas dependências mínimas das fases 2–5 | Consistência após reinício, nenhuma ação duplicada, timeout/cancelamento/limpeza testados e PolicyGate obrigatório |
| 7 — SOC e defesa | Correlação, casos, FIM autenticado e 14 camadas registradas | Telemetria Rust ampliada, hunting, regras, ResponseGrid, contenção/recuperação e perícia de resposta | Eventos/ações rastreáveis, falsos positivos avaliados e suporte por SO testado; controles ativos e recuperação demonstrados |
| 8 — Laboratórios avançados | Cenário sintético e Nmap limitado | QEMU/KVM/Kali, redes/snapshots, Purple Team, ResilienceLab e dinâmica após isolamento | Rotas/DNS/firewall e bloqueio de acesso acidental comprovados; limites de tráfego/CPU/RAM/disco, interrupção/restauração testados |
| 9 — Segurança empresarial | Importadores cloud/identidade/IA, perícia/triagem parcial e RiskGraph em consolidação | Conectores oficiais, Mobile/IoT/OT/ICS, exposição/risco, investigação especializada e inteligência | Escopo/menor privilégio, compatibilidade, testes e limites por integração; nenhuma equivalência comercial ou aquisição móvel presumida |
| 10 — Governança | Registros/evidências/clientes reaproveitáveis | GRC, privacidade/LGPD, terceiros, BIA/RTO/RPO, continuidade e treinamento | Fluxos úteis/testados, retenção, planos e exercícios verificáveis; nenhuma certificação/conformidade integral presumida |
| 11 — Serviços gerenciados | Operador único e organizações/projetos | Monitoramento recorrente, equipes, serviços, incidentes e relatórios por cliente | Isolamento, acesso, responsabilidades e continuidade testados; catálogo comercial limitado aos serviços liberados |
| 12 — Enterprise | Scripts, CI e documentação preparados | Instalação/atualização/desinstalação, hardening, distribuição, suporte, licença, performance e revisão independente | §53.13 cumprido, operação real/recuperação comprovadas, revisão independente e aprovação registradas |

## Fila imediata

O complemento AttackLab Evidence Fusion/Purple Validation de26/10/2026 detalha
as fases deste módulo sem substituir a sequência V6.9. Auditoria dirigida e
plano: [ATTACKLAB-EVIDENCE-FUSION-PLAN.md](docs/ATTACKLAB-EVIDENCE-FUSION-PLAN.md).
Alvos exatos/exclusões no hash aprovado foram implementados na migração010,
com negação antes do cadastro/despacho. Manter essa dependência ao ampliar
executores. O plano versionado da fase1 está ligado ao mandato revisado, com
static.scan integrado a jobs/evidências/resultados (migração011). Próximo passo:
vincular archive.inspect ao plano antes de ampliar formatos TAR/TAR.GZ.

1. Integrações OpenAPI/RiskGraph, perícia/PostgreSQL restrito, painel e restore
   encerradas neste recorte Windows; resultados em VALIDATION_REPORT.md.
2. Recorte de fundação do Authorization Manager entregue: rascunho imutável,
   comprovação/responsável, projeto, revisão explícita e aplicação de perfis,
   bytes/portas, substituição e revogação; manifesto imutável de IPs/exclusões e
   vínculo da execução à revisão aprovada. A tela Autorizações acompanha o ciclo;
   detalhes em AUTHORIZATION_POLICY.md. Planos versionados/API/UI e execução
   estática integrada estão em docs/ASSESSMENT-PLANS.md. Os demais vínculos e jobs
   gerais continuam pendentes; este recorte não encerra toda a fase 1.
3. ZIP em quarentena já implementado e testado. Avançar TAR primeiro e depois
   URL/Git por adaptadores separados, com limites e autorizações próprios, junto
   do plano de avaliação. Registrar cada formato efetivamente aceito sem presumir
   execução automática nem suporte universal.
4. Construir ProofLab sobre esse fluxo e isolamento comprovado. O cenário SOC
   existente não encerra sozinho a nova fase 3.
5. Ampliar assessment, correção/comparação e, conforme dependências, execução,
   SOC, laboratórios e portfólio empresarial.

## Critérios transversais obrigatórios (§53)

- Contratos versionados, identidade de serviço, entradas/eventos/falhas,
  timeout, cancelamento, retries, idempotência e limites explícitos.
- Dados vinculados a organização/projeto com restrições no banco; consultas,
  caches, logs e relatórios sem mistura de clientes.
- Jobs recuperáveis: Pending, Validating, Awaiting Approval, Queued, Running,
  Pausing, Completed, Failed, Cancelled e Timed Out. Registro de job não é
  orquestrador completo.
- Perfis Isolated, Restricted, Authorized Assessment e Production Remediation
  com aplicação real comprovada antes de executar ferramentas.
- Segredos protegidos e adaptadores sem shell inseguro/privilégios elevados
  por padrão; catálogo de testes não comprova executor implementado.
- Testes aplicáveis unitários, integração, E2E, segurança, isolamento, recursos,
  cancelamento, recuperação, instalação, migração e rollback.
- Código, integração, permissões, falhas, limitações, evidências e maturidade
  coerentes para declarar um recorte pronto; liberação profissional é separada.

## Dependências de ambiente preservadas

Debian 13 KDE, PostgreSQL dedicado, identidades de serviço, permissões,
QEMU/KVM/Kali e implantação real continuam marcos de homologação. A antiga
fase de migração foi redistribuída entre fundação, laboratórios e liberação.
Não alterar Windows, partições, firmware ou bootloader por este roadmap.
Scripts de preparação não substituem validação do ambiente real.

## Correspondência histórica V6.6

`docs/ESPECIFICACAO-V6.6.txt` permanece intacta. A tabela não encerra fases
anteriores nem transfere automaticamente maturidade.

| Fase V6.6 | Destino V6.9 |
| --- | --- |
| 0 — Migração/ambiente | Auditoria 0; implantação/homologação nas fases 1, 8 e 12 |
| 1 — Fundação | 1 — Fundação |
| 2 — Evento/alerta/caso/evidência/relatório | 7 — SOC; componentes reaproveitados na fase 3 |
| 3 — SecureBuild | 4 — Assessment; correções na fase 5 |
| 4 — NetworkTrace/ExposureMap | 4, 7 e 9 conforme análise, detecção e exposição |
| 5 — Agente Linux | 7 — SOC e defesa |
| 6 — SOC/casos | 7 — SOC e defesa |
| 7 — Defesa/correção/RiskGraph | 5 — Remediation; 7 — Defesa; 9 — Exposição/risco |
| 8 — Laboratórios | 3 — ProofLab; 8 — Laboratórios avançados |
| 9 — Forense | 7 — Resposta/investigação; 9 — Capacidades especializadas |
| 10 — Malware/memória | 8 — Isolamento/dinâmica; 9 — Análises especializadas |
| 11 — MobileScope | 9 — Mobile Security e perícia móvel |
| 12 — Inteligência | 7 — Hunting/detecção; 9 — Exposição/inteligência |
| 13 — Windows | Compatibilidade transversal em 1, 7 e 12 |
| 14 — Cloud/identidade | 9 — Segurança empresarial |
| 15 — Integrações externas | Adaptadores de 2, 4, 6 e 9; infraestrutura própria preservada |
| 16 — Enterprise | 12 — Enterprise |

Não criar telas vazias para aparentar cobertura. A matriz funcional deve
refletir código e evidências consolidados; divergências são pendências explícitas.
