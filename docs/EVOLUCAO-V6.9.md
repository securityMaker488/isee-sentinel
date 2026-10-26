# Evolução da especificação V6.6 para V6.9

Registro de 25/10/2026. A V6.9 passa a ser a especificação funcional principal.
Este documento compara requisitos e registra o ponto de partida; não declara
novos recursos implementados nem substitui evidências de testes.

Fontes consultadas: V6.9 integral, V6.6 preservada, complemento multiplataforma,
`PROJECT_STATE.md`, `PORTFOLIO_CAPABILITY_MATRIX.md`, seu inventário JSON e o
roadmap anterior. A comparação aproveita o inventário registrado, sem repetir
revisão ampla de código. Novas alterações exigem inspeção dirigida das interfaces.

## Precedência e continuidade

1. V6.9 governa requisitos, prioridades e fases 0–12. O texto original está em
   `ESPECIFICACAO-V6.9.txt`, copiado sem alterar os bytes do anexo.
2. O complemento multiplataforma permanece aplicável: memória no repositório,
   continuidade Windows/Debian, scripts, CI, segredos e Git privado. Ele não
   autoriza publicação automática.
3. V6.6 é referência histórica e conserva detalhes compatíveis do portfólio;
   sua numeração 0–16 não governa mais a sequência de execução.
4. Mantém-se a preferência expressa de retomar do checkpoint, preservar trabalho
   funcional e corrigir erros. Auditoria inicial significa atualizar inventário
   e examinar mudanças relevantes, sem reiniciar o projeto ou repetir a leitura
   indiscriminada de todos os arquivos.

Hashes e referências de retomada estão em `PROMPTS-REGISTRY.md`.

## Mudanças efetivas

| Tema | V6.6 e complemento | Diretriz efetiva da V6.9 |
| --- | --- | --- |
| Primeiro ciclo demonstrável | Evento sintético → regra → alerta → caso → evidência → relatório | Fundação → importar aplicação de laboratório → ambiente isolado → avaliação reproduzível → corrigir cópia → retestar → relatar (§51 e diretriz final) |
| Entrada de trabalho | Importações específicas por motor | Universal Import Lab central (§6): URLs, Git, compactados, instaladores, binários, aplicações móveis, configurações e OpenAPI; identificação, quarentena e plano de avaliação |
| Importação de URL | Auditoria web/API no portfólio | Importador explícito (§7), proteção contra SSRF/redirecionamentos e associação com código/homologação; URL pública não reproduz infraestrutura privada |
| Laboratórios | AttackLab/PurpleMatrix, classes de risco e VMs | ProofLab (§9) para demonstração antes/depois; ResilienceLab (§10) para carga, duração, recursos e interrupção, preservando isolamento e consentimento |
| Autorizações | Escopos por ativo, operação, ambiente e período | Authorization Manager (§35): responsável, evidência de autoridade, testes, limites, aprovações e histórico por projeto; alterações relevantes exigem nova aprovação |
| Remediação | SecureFix com proposta, teste, aprovação e rollback | Remediation Engine (§16) com branches/diffs, regressão e homologação; comparação de duas versões (§17), reteste comparável e riscos residuais |
| Operação | CLI do agente e gerência geral de jobs | Execution Center (§37), interfaces painel/CLI propostas; LAB, ASSESSMENT e PRODUCTION REMEDIATION explicitamente diferenciados (§36) |
| Portfólio empresarial | Serviços técnicos, cloud, identidade e consultoria | Áreas próprias de IoT, OT/ICS, privacidade, GRC, terceiros, continuidade e Human Security (§§21–27); serviços orientados aos problemas do cliente (§38) |
| Engenharia | Contratos, modelos de dados e entregáveis por módulo | Seção 53 obrigatória: estados/recuperação de jobs, contratos versionados, adaptadores, isolamento testado, distribuição, observabilidade e liberação |
| Maturidade | M0–M6 e estados funcionais | Estados descritivos (§45) e classificação de liberação (§53.13), sem promoção automática dos rótulos históricos |
| Roadmap | 0–16, migração Debian na fase 0 | 0–12, começando por auditoria e fundação; implantação Debian vira dependência transversal e continua pendente |

Continuam válidos Rust/TypeScript/Python, React/Vite/Tailwind, Fastify,
PostgreSQL local, operador inicial único, separação entre organizações, custo
controlado, operação local/offline quando compatível, Podman opcional e Windows
preservado. Não há dependência obrigatória de Docker, Kubernetes, Firebase,
Supabase ou API paga. Equipes/MSSP futuros não exigem acrescentar cadastro
público, cobrança ou SaaS agora.

## Correspondência com o trabalho registrado

O checkpoint consultado antecede a consolidação dos testes das últimas
integrações. Uma implementação em finalização não é tratada como validada aqui.

| Requisito V6.9 | Base reaproveitável registrada | Lacuna aberta |
| --- | --- | --- |
| Fundação/clientes/PolicyGate/EvidenceChain | Operador/MFA, organizações/projetos/ativos, escopos, migrações, evidência cifrada e auditoria | Autorização formal ampliada, retenção, novos contratos e homologação Debian |
| Universal Import Lab | Uploads limitados e preservação em módulos existentes | Avaliação central, quarentena de pacotes, expansão segura, identificação multi-formato, Git/URL e plano de análise |
| ProofLab | Cenário SOC sintético e cópia SSH corrigível | Aplicação vulnerável isolada, avaliação ponta a ponta, reteste comparável e relatório integrado |
| Security Assessment | Baseline, dependências/CycloneDX, SARIF, HAR/XML e configurações offline | SAST/DAST abrangentes, lógica de negócios e web/API ativo; OpenAPI aparece em finalização no checkpoint |
| Remediação/comparação | SecureFix propõe/aprova/aplica/verifica/restaura cópia SSH cifrada | Git, software, comparação de duas versões, implantação autorizada e recuperação do host |
| Execution Center | Jobs persistidos, APIs e comandos específicos | Orquestrador central, estados completos, fila, prioridade, cancelamento, retomada e CLI unificada |
| SOC/agentes | Ingestão/correlação, casos/notas/evidências/relatório, Rust autenticado com FIM e baseline aprovada | Processos/serviços/logs/conexões, hunting e operação Linux real; não é EDR/XDR completo |
| Defesa/barreiras | 14 camadas registradas com evidências estáticas | Controles ativos, contenção, restauração de serviços e self-healing no host |
| Laboratórios | Adaptador Nmap opcional e limitado | Kali/KVM/redes/snapshots validados, ProofLab completo, ResilienceLab e testes de isolamento |
| Perícia/malware | Triagem estática, timelines; worker PCAP/PCAPNG/SQLite/plist e API forense registrados | Aquisição de discos/memória/dispositivos, recuperação de apagados, decompilação e dinâmica isolada |
| Cloud/identidade/IA/risco | Importadores IAM/S3/identidades/configuração IA e cálculo limitado de risco | Conectores, testes de modelos/RAG, risco ampliado; RiskGraph estava em finalização sem integração validada no checkpoint |
| Governança/serviços/Enterprise | Clientes, projetos, registros, relatórios parciais e preparação multiplataforma | GRC, privacidade, BIA/RTO/RPO, fornecedores, treinamento de clientes, equipes/MSSP e liberação profissional |

Divergências a consolidar: a matriz V6.6 ainda marca API Security como M0 e
descreve PCAP/PCAPNG como ausentes, enquanto `PROJECT_STATE.md` registra OpenAPI
em finalização e API forense recém-adicionada. RiskGraph também está em transição.
São pendências documentais, não fundamento para presumir módulos completos.
Esta tarefa não altera a matriz nem promove maturidade.

## Obrigações de engenharia da seção 53

| Seção | Obrigação verificável | Consequência nos próximos incrementos |
| --- | --- | --- |
| 53.1 | APIs/dados/eventos, identidade de serviço, versionamento, falhas, timeout, cancelamento, retries, idempotência e limites | Definir contratos antes de conectar importadores/workers; separar responsabilidades e evitar acesso indiscriminado entre módulos |
| 53.2 | Job persistente com projeto/operador/módulo, parâmetros, prioridade, timestamps, limites, resultado, evidências e erros | Modelar Pending, Validating, Awaiting Approval, Queued, Running, Pausing, Completed, Failed, Cancelled e Timed Out; impedir duplicação e recuperar interrupções |
| 53.3 | Modelos versionados, IDs, FKs, índices e isolamento organização/projeto | Acrescentar Assessment/Plan/Run, TestDefinition/Execution, Retest, Comparison e LabEnvironment conforme fluxos reais, sem entidades vazias |
| 53.4 | Quarentena, VMs, redes/snapshots, cotas, monitoramento, expansão segura e limpeza | Não executar software desconhecido automaticamente no host; testar isolamento e falhas com fixtures |
| 53.5 | Isolated, Restricted, Authorized Assessment e Production Remediation | Validar rotas, DNS, interfaces, firewall e redirecionamentos; nomear um perfil não comprova isolamento |
| 53.6 | Segredos centralizados, temporários, cifrados, auditados, rotacionados e recuperáveis | Não expor valores em logs, argumentos, histórico ou relatórios; ampliar retenção/backup protegido |
| 53.7 | Catálogo de testes com objetivo, versão, impacto, requisitos, entradas, CLI/painel, limites, cancelamento, evidências e falsos positivos | Definição aponta implementação e regressão reais; catálogo não equivale a executor funcional |
| 53.8 | Adaptador valida dependência/versão/escopo, parâmetros, limites, resultados e liberação de recursos | Sem shell construído com entrada não confiável ou privilégios administrativos por padrão |
| 53.9 | Instalação, serviços, atualização/migração, diagnóstico, backup/restore, rollback e desinstalação | Reaproveitar scripts; testar instalação/restauração Debian; GPU dedicada não é requisito |
| 53.10 | Logs/health/métricas, jobs, erros, consumo, integrações, VMs e agentes | Diferenciar falha do Sentinel de achado no alvo; redigir dados sensíveis e controlar acesso/retenção |
| 53.11 | Falhas de worker/backend/rede/VM/banco/disco, timeout e reinício | Preservar resultados parciais/histórico, recuperar com segurança e limpar recursos |
| 53.12 | Testes unitários, integração, E2E, segurança, isolamento, recursos, cancelamento, recuperação, instalação/migração/rollback | Compilação isolada é insuficiente; registrar ambiente e testes não executados |
| 53.13 | Critérios de liberação profissional e classificação explícita | Fixture local aprovada não libera atendimento a clientes |
| 53.14 | Arquitetura, contratos, dados, eventos, testes, políticas, ameaças, recuperação, decisões, riscos e evidências | Atualizar documentos correspondentes; mapear nomes novos aos documentos existentes sem duplicações contraditórias |
| 53.15 | Inspeção, riscos/contratos, menor incremento funcional, testes, limitações e próximos passos | Preservar código e retomar pelo checkpoint, sem reescrita indiscriminada |
| 53.16 | Código, interfaces, testes, permissões, falhas, limitações, evidências e maturidade coerentes | Declarar concluído somente o recorte comprovado |

## Pendências em ordem de fases

O plano detalhado está em `../ROADMAP.md`.

1. **Fase 0:** fechar OpenAPI/RiskGraph, PostgreSQL restrito da perícia, browser QA
   e restore atualizado. Não reaproveitar o restore histórico de 14 tabelas como
   comprovação de todas as migrações novas.
2. **Fase 1:** consolidar contratos de avaliação/importação e campos de autorização
   necessários ao primeiro fluxo, com separação de cliente/projeto.
3. **Fase 2:** preservar, identificar e quarentenar artefato de laboratório com
   limites e rejeição de entradas perigosas. URL/Git/outros formatos são recortes
   separados, com suporte explicitamente delimitado.
4. **Fase 3:** aplicação vulnerável local, isolamento comprovado, avaliação,
   evidência, correção na cópia, reteste comparável e relatório.
5. **Fases 4–6:** assessments, remediação/comparação e orquestração/CLI. Antecipar
   somente dependências mínimas necessárias aos incrementos anteriores.
6. **Fases 7–12:** SOC/agentes/defesa, laboratórios avançados, segurança empresarial,
   governança, serviços gerenciados e validação Enterprise.

Instalar Debian não conclui essas capacidades por si só. Validação de sistema,
serviços e VMs é distinta de implementação portátil; particionamento não foi
autorizado por este registro documental.

## Maturidade e entrega

Preservar M0–M6 como rastreabilidade até migrar explicitamente a matriz. M3 de
teste estático não vira automaticamente “validado em laboratório”, “validado
para clientes” ou “disponível comercialmente”. Os estados do §45 e a classificação
de liberação do §53.13 exigem critérios/evidências próprios.

Esta tarefa entrega especificação preservada, comparação, registro de precedência
e roadmap atualizado. Não altera código, não executa testes operacionais novos
e não declara módulos comercialmente prontos.
