# Roadmap V11 — marcos0–5, uma linha de desenvolvimento

Atualizado em02/11/2026. Guia único: docs/GUIA-MESTRE-CONSOLIDADO.md, G27.
Checkpoint: PROJECT_STATE.md. A V11 antecipa Rust Core e execução verificável;
requisitos V6.9/AttackLab continuam no mapa abaixo. Não reescrever componentes
funcionais nem repetir auditoria ampla. Completar trabalho portátil no Windows;
parar para Debian13 KDE quando restarem somente dependências reais desse SO.

## Marcos vigentes

| Marco | Base comprovada / entrega | Próximo gate | Cobertura anterior |
|---|---|---|---|
| M0 Auditoria | Checkpoint/Git, arquitetura real, baseline, inventário110 referências, leitura dirigida de9 e licenças registrados | Manter revisão dirigida de mudanças; não repetir auditoria global. Pesquisa não homologa terceiros | V6.9 fase0; AttackLab A1 |
| M1 Rust Core — em andamento | Agente existente preservado; novo supervisor archive.inspect, contrato/recibo/limites, revalidação durante execução, API/UI/auditoria integradas | Contenção e encerramento após falha do supervisor, runtime seguro por SO, job model recuperável, cotas e cancelamento; integrar sem substituir PolicyGate/evidência | Fases1/6 e pré-requisitos2/3; A2/A6 |
| M2 Web/API | Analisador OpenAPI offline existente | Cliente HTTP Rust com URL exata/DNS/IP fixado/SSRF/redirects, crawler limitado, TLS/headers/JWT/achados; importação URL e Git com escopos próprios; ProofLab autorizado antes de DAST amplo | Fases2/3/4 e Evidence Fusion A3/A4 |
| M3 SecureCode | Regras estáticas, dependências/SARIF existentes | Coordenar Semgrep/Bandit/Trivy/secrets/SCA com licença/versão/limites; correção em cópia/branch, regressão, reteste e relatórios vinculados | Fases4/5; A4 |
| M4 Detection/Security Operations | Eventos/core/SOC/casos/FIM e perícia parcial existentes | Ingestão Sigma/YARA/Suricata/Zeek, confiança/deduplicação, hunting, evidência/timeline, resposta autorizada e recuperação testada | Fase7; A4/A5/A6 |
| M5 Advanced Operations | Recortes atuais de Nmap, perícia, RiskGraph e análises especializados preservados | Red/Purple, DFIR/reversão/malware, mobile/cloud/IA/IoT/criptografia; QEMU/Kali e isolamento comprovado. Governança, serviços e liberação somente com gates operacionais anteriores | Fases8–12; A3–A6 |

M0 foi atendido neste recorte dirigido, sem alegação de auditoria exaustiva.
Nenhum dos marcos funcionais M1–M5 está completo. Os M0–M6 da matriz antiga são
**maturidade**, distintos desses marcos. Não converter rótulos em prontidão.

## Próximo incremento concreto

1. M1: preservar o supervisor de um único worker confiável. Projetar e implementar
   contenção de processo/árvore e encerramento quando o supervisor morre, com
   testes reais de PID e limites por SO. Não aceitar plugins arbitrários enquanto
   essas garantias estiverem ausentes. Onde a prova exigir Linux, registrar o
   teste correspondente para Debian sem afirmar validação pelo Windows.
2. Completar contratos de runtime/job model, cancelamento/recuperação e cotas.
   Qualquer novo estado SQL exige nova migração, nunca reescrever001–013.
   Preservar identidade, revisão/hash de autorização, evidência e idempotência.
3. M2: URL via cliente controlado, depois Git por adaptador próprio. Aprovação
   Nmap/IPv4 não concede HTTP; testar DNS/redirect/bytes/tempo em servidor sintético.
   ZIP/TAR e planos já entregues não devem ser refeitos. Gobuster começa offline.
4. Seguir M3–M5 nas dependências acima, mantendo ProofLab, remediação/reteste,
   governança e liberação do escopo anterior. Catálogo não é executor implementado.

Auditoria/decisões: docs/RUST-ENGINES.md e registro de pesquisa interno.
Resultados e limitações de cada incremento: VALIDATION_REPORT.md.

## Cobertura V6.9 preservada — não é uma segunda fila

| Fase | Escopo e base disponível | Próximo incremento / dependências | Evidência de conclusão do recorte |
| --- | --- | --- | --- |
| 0 — Auditoria | Inventário/arquitetura; OpenAPI/RiskGraph/perícia integrados, QA/restore e auditoria dirigida AttackLab registrados; prompts consolidados | Manter apenas revisão dirigida de novos requisitos/alterações e coerência documental | Resultados em VALIDATION_REPORT.md; não reiniciar revisão integral |
| 1 — Fundação | React/Fastify/PostgreSQL, MFA, clientes/projetos, PolicyGate, escopos e evidências; Authorization Manager com responsável, comprovação cifrada, revisão/aprovação, perfis e limites aplicados | Plano completo de avaliação/importação e contratos de execução geral; ampliar os perfis junto de cada executor, sem liberar ações ainda indisponíveis | Testes de identidade, isolamento organização/projeto, migrações, backup/restore e falhas; testes de aprovação, substituição/revogação, bytes e portas; homologação Debian registrada separadamente |
| 2 — Universal Import Lab | Uploads e análises específicas fornecem partes do fluxo | Preservar/identificar/quarentenar artefato próprio; expansão segura de ZIP/TAR, URL e Git por adaptadores separados | Limites, hashes, travessia, links, expansão, erros/limpeza e permissão testados; nenhuma execução automática de software desconhecido no host |
| 3 — ProofLab | SOC sintético e SecureFix de cópia reaproveitáveis | Aplicação vulnerável local, isolamento e cenário integrado à importação/avaliação | Importar → avaliar → evidência → corrigir cópia → retestar comparavelmente → relatar, identificado como laboratório; isolamento/recuperação testados |
| 4 — Security Assessment | Baseline, analisadores offline e OpenAPI JSON integrados | Web/API, catálogo de testes, SAST/SCA e DAST controlado por etapas; ferramentas/feeds com origem/versão/licença | Positivos/negativos, entradas malformadas, limites, evidências e relatório; ausência de achado não implica segurança |
| 5 — Remediation | Ciclo reversível de cópia SSH cifrada | Git, regressão, homologação, comparação e reteste vinculado ao achado; produção exige aprovação específica | Correção testada, risco residual, original/diff/aprovação, verificação e rollback; cópia no banco não equivale a alteração do host |
| 6 — Execution Center | APIs, jobs registrados e CLIs específicas | Fila PostgreSQL, prioridade, estados completos, cancelamento, retomada e CLI; priorizado agora em M1 pela V11 | Consistência após reinício, nenhuma ação duplicada, timeout/cancelamento/limpeza testados e PolicyGate obrigatório |
| 7 — SOC e defesa | Correlação, casos, FIM autenticado e 14 camadas registradas | Telemetria Rust ampliada, hunting, regras, ResponseGrid, contenção/recuperação e perícia de resposta | Eventos/ações rastreáveis, falsos positivos avaliados e suporte por SO testado; controles ativos e recuperação demonstrados |
| 8 — Laboratórios avançados | Cenário sintético e Nmap limitado | QEMU/KVM/Kali, redes/snapshots, Purple Team, ResilienceLab e dinâmica após isolamento | Rotas/DNS/firewall e bloqueio de acesso acidental comprovados; limites de tráfego/CPU/RAM/disco, interrupção/restauração testados |
| 9 — Segurança empresarial | Importadores cloud/identidade/IA, perícia/triagem parcial e RiskGraph em consolidação | Conectores oficiais, Mobile/IoT/OT/ICS, exposição/risco, investigação especializada e inteligência | Escopo/menor privilégio, compatibilidade, testes e limites por integração; nenhuma equivalência comercial ou aquisição móvel presumida |
| 10 — Governança | Registros/evidências/clientes reaproveitáveis | GRC, privacidade/LGPD, terceiros, BIA/RTO/RPO, continuidade e treinamento | Fluxos úteis/testados, retenção, planos e exercícios verificáveis; nenhuma certificação/conformidade integral presumida |
| 11 — Serviços gerenciados | Operador único e organizações/projetos | Monitoramento recorrente, equipes, serviços, incidentes e relatórios por cliente | Isolamento, acesso, responsabilidades e continuidade testados; catálogo comercial limitado aos serviços liberados |
| 12 — Enterprise | Scripts, CI e documentação preparados | Instalação/atualização/desinstalação, hardening, distribuição, suporte, licença, performance e revisão independente | §53.13 cumprido, operação real/recuperação comprovadas, revisão independente e aprovação registradas |

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
