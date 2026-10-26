# Inventário e matriz de implementação

Atualização: 23/10/2026, especificação vigente V6.5. Esta é uma fundação integrada, não o produto enterprise completo. O estado refere-se à capacidade descrita na linha, não a todo o escopo do prompt mestre. A maturidade M0–M6 está definida em `COMPARACAO-V5-V6.3.md`; fases de implantação estão em `FASES-V6.5.md`.

## Vocabulário de estados

| Estado | Critério |
|---|---|
| Planejado | Requisito e fronteira definidos, sem fluxo executável entregue |
| Em desenvolvimento | Código parcial ou integração ainda incompleta |
| Implementado | Fluxo e contratos presentes; resultado de execução ainda precisa ser registrado |
| Testado | Casos executados, ambiente e resultados registrados; vale apenas para esses casos |
| Validado | Revisão independente e aceitação contextual documentadas; não significa certificação |
| Pronto para operação interna | Homologação do ambiente, identidade, recuperação, observabilidade e responsáveis concluída |
| Apto à comercialização | Além da operação, avaliação jurídica/licenças, suporte, privacidade, capacidade e compromissos comerciais concluída |

Nesta entrega nenhum módulo é declarado validado, pronto para operação interna ou apto à comercialização. Testes automatizados não são validação independente. A V6.5 passou 37 testes JS (17 core, 19 API, 1 configuração), e os 19 casos API passaram também em PostgreSQL 18.6 temporário isolado com identidade runtime restrita. Rust passou 9; Python passou 8, com 1 caso Unix ignorado no Windows. A restauração nativa comparou 14 tabelas sem diferenças e verificou a cadeia de auditoria. O registro de escopo e limitações é `VALIDATION.md`; Debian/systemd não foram homologados.

## Módulos

| Módulo / plano | Fatia entregue ou capacidade futura | Estado da fatia / limitação |
|---|---|---|
| Command Center / Control | Login e visão de dados persistidos, ativos, análises, evidências, eventos, incidentes e auditoria | Implementado; homologação visual/acessibilidade e escala ainda limitadas |
| Identidade e TrustGuard / Control | Fundador único, Argon2id, MFA TOTP obrigatório, sessão expirada/revogada e recuperação por CLI privada | M3 no recorte testado V6.5; TrustGuard contínuo, WebAuthn e elevação temporária planejados |
| Organizações/projetos e ativos / Control | Contexto de organização da sessão do fundador, projetos com referência de contrato e ativos | M3 no recorte API/UI; criação, troca de contexto e isolamento testados no navegador; serviços e workflow contratual completo planejados |
| PolicyGate / Control | Negação por padrão, papel, organização, ativo, ambiente, operação e autorização temporal | Implementado; contratos completos, políticas de emergência e aprovadores múltiplos planejados |
| Auditoria / Control | Eventos de operações e custódia, encadeamento de hashes, proteção contra UPDATE/DELETE ordinários | Implementado; ancoragem externa e proteção contra DBA comprometido planejadas |
| Jobs / Analysis | Estado SQL, executor local limitado, interrupção explícita na inicialização | Implementado; fila distribuída, leases, cancelamento e retries planejados |
| SecureBuild / Analysis | Regras versionadas de configuração e indicadores de segredos em textos enviados | Implementado; não é SAST/DAST completo, SCA ou pentest |
| RiskGraph / Analysis | Função de priorização explicável de achados no pacote core, integrada ao relatório JSON | M3 no recorte de cálculo e relatório testado; sem grafo na UI; CVSS/EPSS/KEV e correlação entre ativos planejados |
| EvidenceChain / Data | Evidência cifrada, SHA-256 dos bytes, auditoria de acesso e verificação | Implementado; retenção, transferências formais, custódia jurídica e armazenamento WORM planejados |
| BarrierMatrix / Defense | Catálogo das 14 camadas e avaliações estáticas com limites explícitos | Implementado parcialmente; aplicação e verificação runtime das camadas planejadas |
| DefenseFlow / Defense | Eventos recebidos, correlação, alertas e incidentes | M3 no recorte API/SOC; coletores, correlação ampla e contenção planejados |
| Detection Engine / Data + Defense | Regra AUTH-FAIL-5 versionada, deduplicação por ID externo, alerta persistido, incidente e triagem de falso positivo | M3 no recorte testado V6.5; regra isolada não confirma invasão |
| Endpoint Agent / Data | Protótipo Rust offline de hash de um arquivo autorizado; contrato AgentObservation v1 | M1 offline, testado no Windows; sem serviço residente, integração API ou coleta journald/ETW |
| Worker Python de integridade / Analysis | Valida estrutura de AgentObservation v1 em arquivo local, sem seguir o path mencionado | M1 offline, testado com o protótipo Rust; não autentica origem nem recalcula o hash do arquivo original |
| IdentityGuard / Analysis | Identidades, MFA, privilégios, AD/LDAP/cloud, leitura autorizada | Planejado/M0; autenticação do Sentinel não é auditoria de diretório externo |
| CloudShield / Analysis | AWS/Azure/GCP, IAM, storage, rede, IaC e containers | Planejado/M0; nenhum provedor conectado |
| ExposureMap / Analysis | Inventário e correlação de exposição de ativos | Planejado/M0; cadastro manual não prova descoberta de exposição |
| Threat Hunting / Analysis | Hipóteses investigativas e consultas sobre telemetria | Planejado/M0 além das listas atuais |
| Vulnerability Management / Analysis | Histórico, deduplicação, exceções e retestes de vulnerabilidades | Planejado/M0 além dos achados atuais |
| Validation Lab / Laboratory | Medir falsos positivos/negativos, segurança de agentes, isolamento, recuperação e performance | Planejado/M0 como módulo; suítes unitárias/integração existentes são insumo |
| ResponseGrid / Defense | Lista de incidentes e referências a eventos | Implementado parcialmente; workflow de resposta, aprovações, comunicação e lições aprendidas planejados |
| Reporting / Analysis | Consolidação de resultados de análise e evidências | Implementado parcialmente; modelos comerciais, assinatura e gestão persistente de relatórios planejados |
| CanaryWatch / Defense | Tokens e arquivos-isca autorizados, alertas | Planejado |
| IntegrityWatch / Defense | Baselines de arquivos, políticas e configurações; alertas de desvio | Planejado; hash de evidência não equivale a monitoramento contínuo |
| ShieldScore / Analysis | Pontuação de maturidade explicável e com cobertura demonstrada | Planejado; nenhum percentual de proteção é prometido |
| SafeDeploy / Defense | Aprovação, implantação gradual, health check e rollback | Planejado |
| AutoDefense / Defense | Detectar → investigar → preservar → propor → aprovar → executar → reavaliar | Planejado; nenhuma alteração autônoma de produção |
| Self-Healing / Defense | Recuperação verificada, limite de tentativas e escalonamento | Planejado |
| SecureFix / Analysis + Defense | Patch isolado, diff, teste, revisão, deploy e reteste | Planejado |
| AttackLab / Laboratory | VMs, redes isoladas, cenários e snapshots autorizados | Planejado; nenhuma VM criada ou teste ofensivo executado |
| PurpleMatrix / Laboratory | Exercícios controlados e medição de detecções | Planejado |
| DiskLab / Analysis | Imagens de disco, formatos forenses, timeline e buscas | Planejado |
| MobileScope / Analysis | Backups/exportações móveis acessíveis legitimamente | Planejado; sem bypass de autenticação |
| DeepTrace / Analysis | Correlação forense de memória, arquivos, processos e eventos | Planejado |
| MalwareLens / Laboratory | Análise estática e sandbox descartável de amostras autorizadas | Planejado; não executar amostras no host |
| NetworkTrace / Analysis | PCAP/PCAPNG, fluxos, protocolos e relações | Planejado |
| IntelScope / Intelligence | OSINT de ativos autorizados, fontes e histórico | Planejado |
| ThreatPulse / Intelligence | Indicadores, confiança, deduplicação e correlação | Planejado |
| CryptoGuard / Analysis | Certificados, protocolos, algoritmos e gestão de chaves | Planejado; regras SecureBuild não equivalem ao módulo |
| AI Security / Analysis | Auditoria de aplicações/agentes de IA, permissões e prompt injection | Planejado; sem avaliação de modelo ou agente externo |
| Sentinel Intelligence Assistant / Intelligence | Explicações e propostas com ferramentas tipadas, fontes e PolicyGate | Planejado; nenhum provedor ou LLM conectado |
| Integrations / Data | Conectores revisados, credenciais segregadas, licenças e quotas | Planejado; ferramentas no inventário não estão instaladas/integradas |
| External Backend Security Adapters / Analysis | Firebase, Supabase, AWS, Azure, GCP, PostgreSQL e MySQL externos auditáveis | M0/fase 8; sem dependência interna ou adaptador implementado; aguarda base validada |
| Camada Podman rootless / Laboratory | Workers opcionais com imagem por digest, quotas, mounts e rede restritos | M0; não instalado, sem substituir VM em experimentos perigosos |
| System Health / Control | Saúde básica do serviço | Implementado parcialmente; SLO, alerta externo e monitoramento contínuo planejados |
| Settings / Control | Variáveis de ambiente e CLI privada | Implementado parcialmente; painel amplo de configuração planejado |
| Comercialização | Licenciamento, implantação privada, SaaS e cobrança | Planejado; cobrança adiada |

As 28 seções V5 e 33 seções V6.3 são organizadas por esses módulos: SOC/Blue Team correspondem a DefenseFlow/Detection Engine; Red Team/AttackLab a laboratório; Purple Team a PurpleMatrix; Digital Forensics a DiskLab/DeepTrace/EvidenceChain; Mobile Forensics a MobileScope; Malware Research a MalwareLens; Network Intelligence a NetworkTrace; OSINT a IntelScope; Threat Intelligence a ThreatPulse. Não é necessário exibir um menu vazio para representar um requisito planejado.

## As 14 camadas

| Camada | Evidência possível na fundação | Ainda necessário para confirmar eficácia |
|---|---|---|
| 1 Edge Security | Controles locais da API, como limites de requisição | WAF, testes de abuso, métricas, revisão de bloqueios; mitigação volumétrica depende de upstream |
| 2 Network Segmentation | Bind local do Sentinel | Firewall, fluxos permitidos, isolamento e teste de comunicação lateral |
| 3 Zero Trust Identity | MFA e autorização do Sentinel | Medir todos os ativos, identidades de serviço, WebAuthn e reautenticação |
| 4 Application & API Security | Validação, CSRF, regras de configuração nos arquivos | Testes de aplicação em execução, BOLA, XSS, SSRF e lógica contextual |
| 5 Database Security | SQL parametrizado e organização nas consultas/relacionamentos; servidor verifica esquema sem DDL | Validar credenciais separadas/grants no ambiente real, RLS quando apropriado, restore e revisão de privilégios |
| 6 Cryptography & Secret Protection | Argon2id/AES-GCM e indícios estáticos de TLS/segredos | TLS real, rotação, custódia da chave e política de certificados |
| 7 Endpoint & Server Hardening | Regras de configuração SSH enviada | Configuração efetiva, precedência, atualizações e host em execução |
| 8 Software Supply Chain | Lockfile e inventário local | SBOM padronizado, proveniência, gates CI e rotina de atualização |
| 9 AI & Agent Security | Ausência de executor de IA nesta versão | Avaliação de prompt injection, ferramentas tipadas e limites no módulo futuro |
| 10 Intrusion Detection | Uma regra determinística sobre eventos recebidos | Sensores autenticados, cobertura, métricas e validação de cenários |
| 11 Threat Containment | Nenhum executor | Playbook autorizado, reversibilidade, revisão e evidências |
| 12 Autonomous Remediation | Nenhum executor | Patch, testes, aprovação, implantação, reteste e rollback |
| 13 Recovery & Resilience | Backup/restauração PostgreSQL da fixture testados em banco separado, 14 tabelas idênticas e auditoria íntegra | Homologação operacional, RPO/RTO medidos, custódia da chave, cópia externa e falhas simuladas |
| 14 Audit, Forensics & Evidence | Evidência, hashes, auditoria e verificação | Custódia completa, retenção, timeline forense, ancoragem independente |

`pass`, `fail` e `not_evaluated` em um controle descrevem o teste específico. `runtimeVerified=false` impede tratar análise estática como barreira ativa. Ausência de achado não prova ausência de vulnerabilidade.

## Aceitação A–H e validação pendente

| Demonstração | Escopo nesta entrega | Evidência de aceitação necessária |
|---|---|---|
| A Auditoria | Fatia implementada: arquivos autorizados → análise → achados/evidência/relatório | Rodar fixture insegura e corrigida; conferir regra, hash, organização e relatório |
| B Barreiras | Parcial: avaliações estáticas e catálogo | Validar controle em runtime antes de afirmar eficácia |
| C Defesa | Fatia V6.5 testada: eventos `auth.failure` → correlação → alerta persistido → incidente | Regra/segregação/deduplicação/triagem testadas na API; exibição de cenário sintético exercitada no SOC; falta sensor autenticado |
| D AutoDefense | Planejado | Fluxo completo de patch com aprovação, aplicação e reteste no lab |
| E Self-Healing | Planejado | Falha controlada, recuperação e integridade preservada |
| F Purple Team | Planejado | Cenário isolado, eventos e comparação defensiva real |
| G Forense | Parcial: registro/recuperação de bytes e hash | Custódia e acesso demonstráveis; timeline e formatos forenses ainda ausentes |
| H Segurança do Sentinel | Fatia implementada | Negativos de autenticação/MFA, sessão revogada/expirada, CSRF, cross-org, papel e prazo |

Testes ainda necessários além da suíte inicial: concorrência sustentada no PostgreSQL; falha de banco/processo; disco cheio; recuperação operacional com custódia da chave; falha/perda de chave; revogação de escopo durante jobs externos futuros; acessibilidade abrangente; autorização dos próximos endpoints; fuzzing dos parsers; segurança do processo de atualização. A restauração da fixture e a detecção criptográfica de adulteração já foram exercitadas no escopo de `VALIDATION.md`. Cada resultado deve guardar comando, ambiente, data, contagem, código de saída, limitações e responsável. Um caso não executado permanece pendente.
