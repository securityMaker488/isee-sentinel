# Matriz funcional central — I.See Sentinel V6.9

Atualizada em26/10/2026 a partir dos incrementos e testes registrados. M0–M6 é a escala histórica; nenhum módulo alcançou M4–M6. EstadosV6.9 de liberação profissional não são inferidos dos testes locais. Não há recurso liberado para clientes ou distribuição comercial. Dados estruturados: docs/portfolio-capabilities.json. Resultados: VALIDATION_REPORT.md. Referências não implicam equivalência a produtos externos.

## private-core — Command Center / PolicyGate

| Campo | Registro |
|---|---|
| Ferramenta de referência | Padrões OWASP; PostgreSQL |
| Problema | Operação privada, autenticação, autorização e isolamento |
| Funcionalidades desejadas / recorte | MFA TOTP, operador único, clientes/projetos, escopos, sessão, auditoria |
| Módulo | Command Center / PolicyGate |
| Implementação | Nativa + bibliotecas |
| Dependências | Node 24, Fastify, PostgreSQL |
| Sistema operacional | Multiplataforma; Debian por homologar |
| Rede | Não após instalação |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Sem SaaS; isolamento por organização e vínculo de projeto via ativo; retenção automatizada pendente |
| Testes necessários / disponíveis | apps/api/test/integration.test.ts; isolamento/MFA/CSRF/migrações; resultados em VALIDATION_REPORT.md |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Integrada · M3 |
| Prioridade | P0 |

## securebuild — SecureBuild

| Campo | Registro |
|---|---|
| Ferramenta de referência | ASVS/WSTG; SAST |
| Problema | Revisar arquivos autorizados |
| Funcionalidades desejadas / recorte | 6 regras estáticas SSH/TLS/CORS/segredos, evidência, relatório |
| Módulo | SecureBuild |
| Implementação | Nativa |
| Dependências | TypeScript |
| Sistema operacional | Multiplataforma |
| Rede | Não |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não é SAST interprocedural nem DAST; autorização e lógica de negócio incompletas |
| Testes necessários / disponíveis | packages/core/test/core.test.ts |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Limitada · M3 |
| Prioridade | P0 |

## dependencies — SecureBuild / Supply Chain

| Campo | Registro |
|---|---|
| Ferramenta de referência | Syft, OSV-Scanner, Trivy, Gitleaks, Semgrep |
| Problema | Inventariar dependências e exposição |
| Funcionalidades desejadas / recorte | npm lock, CycloneDX, procedência e higiene; SARIF importado |
| Módulo | SecureBuild / Supply Chain |
| Implementação | Nativa + importação |
| Dependências | JSON, saxes para XML de rede |
| Sistema operacional | Multiplataforma |
| Rede | Não; bases CVE futuras exigem atualização |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Sem feed CVE atualizado; sem scanner externo instalado; licença de futuras edições a verificar |
| Testes necessários / disponíveis | packages/core/test/analysis.test.ts (execução pendente ao registrar) |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P1 |

## api-security — SecureBuild / API

| Campo | Registro |
|---|---|
| Ferramenta de referência | OWASP API Top 10, ZAP |
| Problema | Avaliar contratos e controle por recurso |
| Funcionalidades desejadas / recorte | Auditoria estática JSON OpenAPI 3.0/3.1, referências locais limitadas, autenticação declarada, HTTP, parâmetros e limites |
| Módulo | SecureBuild / API |
| Implementação | Nativa |
| Dependências | TypeScript; sem chamadas de rede |
| Sistema operacional | Multiplataforma |
| Rede | Testes ativos exigem rede autorizada |
| Licenciamento | Não determinada; verificar edição/versão/API antes de integrar |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Sem DAST nem comprovação de BOLA, exploração ou implementação real; YAML e referências externas indisponíveis |
| Testes necessários / disponíveis | 15 testes do motor + 5 de integração API; entrada/preservação/relatório/isolamento |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P1 |

## agent-fim — Endpoint Agent / IntegrityWatch

| Campo | Registro |
|---|---|
| Ferramenta de referência | Agentes de integridade; padrões públicos |
| Problema | Observar mudanças de arquivos |
| Funcionalidades desejadas / recorte | Rust, hash, envio HMAC, nonce, validade, revogação, baseline explícita, alerta |
| Módulo | Endpoint Agent / IntegrityWatch |
| Implementação | Nativa |
| Dependências | Rust, reqwest/rustls, backend |
| Sistema operacional | Windows compilado; Linux depende homologação |
| Rede | Agente precisa alcançar backend; pode ser rede local |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Somente arquivos explícitos; não EDR, não processos/serviços/ETW; comprometimento do host limita confiança |
| Testes necessários / disponíveis | apps/api/test/agents.test.ts: 5 passaram; Rust/Python em teste nesta alteração |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P0 |

## endpoint-full — Endpoint Agent / XDR

| Campo | Registro |
|---|---|
| Ferramenta de referência | APIs Linux/Windows; OpenTelemetry |
| Problema | Telemetria operacional |
| Funcionalidades desejadas / recorte | Processos, serviços, journald, autenticação, conexões; Windows Event Log/ETW |
| Módulo | Endpoint Agent / XDR |
| Implementação | Adaptadores de SO planejados |
| Dependências | APIs oficiais e privilégios mínimos |
| Sistema operacional | Adaptadores distintos Linux e Windows |
| Rede | Backend local ou rede autorizada |
| Licenciamento | Não determinada; verificar edição/versão/API antes de integrar |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não assumir paridade Windows/Linux nem XDR completo |
| Testes necessários / disponíveis | Fixtures por SO, perda/replay/volume e isolamento |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Não iniciada · M0 |
| Prioridade | P1 |

## detection — Detection Engine / DefenseFlow

| Campo | Registro |
|---|---|
| Ferramenta de referência | Sigma (referência futura) |
| Problema | Correlacionar e triar eventos |
| Funcionalidades desejadas / recorte | 5 falhas em janela, dedup, isolamento sintético, fila, alertas |
| Módulo | Detection Engine / DefenseFlow |
| Implementação | Nativa |
| Dependências | PostgreSQL, regras TypeScript |
| Sistema operacional | Multiplataforma |
| Rede | Não, exceto recepção remota |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Duas famílias de detecção com FIM em testes; editor Sigma e hunting avançado pendentes |
| Testes necessários / disponíveis | apps/api/test/integration.test.ts |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Integrada · M3 |
| Prioridade | P0 |

## cases — ResponseGrid / DefenseFlow

| Campo | Registro |
|---|---|
| Ferramenta de referência | Fluxos SOC/IR |
| Problema | Investigar incidentes |
| Funcionalidades desejadas / recorte | Notas, estados, eventos, evidências, histórico |
| Módulo | ResponseGrid / DefenseFlow |
| Implementação | Nativa |
| Dependências | PostgreSQL, migração 004 |
| Sistema operacional | Multiplataforma |
| Rede | Não |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Relatório profissional e classificação de impacto ainda parciais |
| Testes necessários / disponíveis | apps/api/test/operations.test.ts: 6 testes passaram; painel em desenvolvimento |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P0 |

## remediation — SecureFix / SafeDeploy

| Campo | Registro |
|---|---|
| Ferramenta de referência | Fluxos de controle de mudanças |
| Problema | Revisar correção com retorno verificável |
| Funcionalidades desejadas / recorte | Patch SSH conservador, aprovação, aplicação, verificação, rollback de cópia |
| Módulo | SecureFix / SafeDeploy |
| Implementação | Nativa |
| Dependências | Artefatos cifrados, laboratório, escopo |
| Sistema operacional | Multiplataforma |
| Rede | Não |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | A aplicação altera somente artefato armazenado; não configura nem reinicia host |
| Testes necessários / disponíveis | apps/api/test/operations.test.ts |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Limitada · M3 |
| Prioridade | P1 |

## response-live — AutoDefense / Self-Healing / ResponseGrid

| Campo | Registro |
|---|---|
| Ferramenta de referência | NIST IR (referência) |
| Problema | Contenção e recuperação de serviços |
| Funcionalidades desejadas / recorte | Runbooks, níveis 0–3, ação reversível, aprovação crítica, restore |
| Módulo | AutoDefense / Self-Healing / ResponseGrid |
| Implementação | Planejada |
| Dependências | Executor com privilégios delimitados; backends de serviço |
| Sistema operacional | Específico por SO |
| Rede | Conforme alvo |
| Licenciamento | Não determinada; verificar edição/versão/API antes de integrar |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Executor crítico permanece bloqueado; IA não muda sua própria autorização |
| Testes necessários / disponíveis | Testes de falha e reversão reais ainda necessários |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Não iniciada · M0 |
| Prioridade | P2 |

## network-import — NetworkTrace / ExposureMap

| Campo | Registro |
|---|---|
| Ferramenta de referência | Wireshark/TShark, tcpdump, Zeek, NetworkMiner, Nmap |
| Problema | Examinar tráfego e exposição exportados |
| Funcionalidades desejadas / recorte | HAR, XML Nmap, fluxos/importação PCAP futura |
| Módulo | NetworkTrace / ExposureMap |
| Implementação | Nativa + importadores |
| Dependências | saxes; PCAP parser futuro |
| Sistema operacional | Multiplataforma |
| Rede | Importação offline |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | HAR e XML não equivalem a PCAP/PCAPNG; captura, TLS e reassembly não implementados |
| Testes necessários / disponíveis | packages/core/test/analysis.test.ts |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P1 |

## lab-scan — AttackLab / ExposureMap

| Campo | Registro |
|---|---|
| Ferramenta de referência | Nmap |
| Problema | Inventariar portas de alvo autorizado |
| Funcionalidades desejadas / recorte | Adaptador Nmap com um IPv4 de laboratório e portas limitadas |
| Módulo | AttackLab / ExposureMap |
| Implementação | Open-Source/Laboratory Adapter |
| Dependências | Nmap externo configurado, escopo e timeout |
| Sistema operacional | Depende Nmap local; Debian por homologar |
| Rede | Apenas alvo explicitamente cadastrado |
| Licenciamento | Verificação oficial em andamento; não redistribuído |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Adaptador opcional; IPv4lab,16portas,30sNmap/40sprocesso,1concorrente. Nmap real não homologado, sem exploração nem isolamentoVM automático; endereço/exclusões ainda não integram o hash da autorização. Ampliar somente após manifesto aprovado |
| Testes necessários / disponíveis | 10 testes com executor injetado; não representam varredura real |
| Evidências | Adaptador limitado e testes registrados; auditoria e plano em docs/ATTACKLAB-EVIDENCE-FUSION-PLAN.md. Gobuster e demais novos adaptadores ainda ausentes |
| Estado real | Em validação · M2 |
| Prioridade | P1 |

## purple — PurpleMatrix / AttackLab

| Campo | Registro |
|---|---|
| Ferramenta de referência | MITRE ATT&CK / laboratórios Kali |
| Problema | Validar detecções em laboratório |
| Funcionalidades desejadas / recorte | Cenário sintético existente; catálogo Atomic de metadados e validação manual esperada/observada planejados no complemento AttackLab |
| Módulo | PurpleMatrix / AttackLab |
| Implementação | Nativa + laboratório futuro |
| Dependências | VM QEMU/KVM e rede isolada para cenários completos |
| Sistema operacional | KVM Linux; outros hosts por avaliar |
| Rede | Laboratório isolado |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Cenário sintético não comprova contenção de ataques nem cobertura ATT&CK; Suricata/Sigma/YARA/Auditd/Atomic não integrados |
| Testes necessários / disponíveis | scripts/browser-qa.cjs cenário sintético |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Limitada · M3 |
| Prioridade | P2 |

## disk — DiskLab / DeepTrace

| Campo | Registro |
|---|---|
| Ferramenta de referência | Autopsy, The Sleuth Kit, FTK/FTK Imager, EnCase, X-Ways |
| Problema | Investigar imagens de computador |
| Funcionalidades desejadas / recorte | RAW/DD/E01, NTFS/FAT/exFAT/ext4, diretórios, timestamps, busca |
| Módulo | DiskLab / DeepTrace |
| Implementação | Adaptadores planejados |
| Dependências | TSK/libewf ou alternativas a selecionar |
| Sistema operacional | Conforme ferramenta; validar Debian/Windows |
| Rede | Offline após instalar |
| Licenciamento | Não determinada; verificar edição/versão/API antes de integrar |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Sem aquisição/recuperação de discos; ferramentas comerciais são referências, licença/API não presumidas |
| Testes necessários / disponíveis | Imagens conhecidas, hashes e exportação reprodutível necessários |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Não iniciada · M0 |
| Prioridade | P2 |

## timeline — DeepTrace / EvidenceChain

| Campo | Registro |
|---|---|
| Ferramenta de referência | Fluxos forenses documentados |
| Problema | Normalizar eventos já exportados |
| Funcionalidades desejadas / recorte | Importação sentinel.timeline.v1, ordenação, hashes, limites |
| Módulo | DeepTrace / EvidenceChain |
| Implementação | Nativa |
| Dependências | JSON de origem autorizada |
| Sistema operacional | Multiplataforma |
| Rede | Não |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não indexa imagens, não extrai artefatos apagados; timestamps dependem da fonte |
| Testes necessários / disponíveis | packages/core/test/analysis.test.ts |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P1 |

## mobile — MobileScope

| Campo | Registro |
|---|---|
| Ferramenta de referência | ALEAPP, iLEAPP, Cellebrite, Magnet AXIOM, Oxygen |
| Problema | Analisar backups legitimamente obtidos |
| Funcionalidades desejadas / recorte | SQLite, plist, arquivos, metadados, linha do tempo Android/iOS |
| Módulo | MobileScope |
| Implementação | Adaptadores planejados |
| Dependências | Parsers e fixtures autorizadas |
| Sistema operacional | Conforme bibliotecas |
| Rede | Offline após instalar |
| Licenciamento | Não determinada; verificar edição/versão/API antes de integrar |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não desbloqueia dispositivos; sem presunção de APIs/licenças comerciais |
| Testes necessários / disponíveis | Backups sintéticos com resultados conhecidos necessários |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Não iniciada · M0 |
| Prioridade | P3 |

## malware-static — MalwareLens

| Campo | Registro |
|---|---|
| Ferramenta de referência | Ghidra, IDA Pro, YARA, ferramentas binárias |
| Problema | Triar artefatos sem execução |
| Funcionalidades desejadas / recorte | Hash, PE/ELF, entropia, strings e padrões lexicais limitados |
| Módulo | MalwareLens |
| Implementação | Nativa; adaptadores futuros |
| Dependências | Envelope binário base64 limitado |
| Sistema operacional | Multiplataforma |
| Rede | Não |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não declara arquivo benigno/malicioso; não há decompilação, assinatura Authenticode ou YARA integrado |
| Testes necessários / disponíveis | packages/core/test/analysis.test.ts |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P2 |

## malware-dynamic — MalwareLens / DeepTrace

| Campo | Registro |
|---|---|
| Ferramenta de referência | Volatility 3, Cuckoo e alternativas mantidas |
| Problema | Examinar execução e memória |
| Funcionalidades desejadas / recorte | Dumps, Volatility, processos, conexões, alterações |
| Módulo | MalwareLens / DeepTrace |
| Implementação | Planejada |
| Dependências | Laboratório Classe C validado, isolamento e snapshots |
| Sistema operacional | Dependente da plataforma |
| Rede | Rede de amostra bloqueada/controlada |
| Licenciamento | Não determinada; verificar edição/versão/API antes de integrar |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não executar malware real no host; VM não é garantia de contenção |
| Testes necessários / disponíveis | Amostras benignas, contenção e reprodutibilidade necessários |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Não iniciada · M0 |
| Prioridade | P3 |

## intel — IntelScope / ThreatPulse

| Campo | Registro |
|---|---|
| Ferramenta de referência | Maltego, SpiderFoot, theHarvester, Shodan |
| Problema | Enriquecer indicadores com procedência |
| Funcionalidades desejadas / recorte | Indicadores, DNS, domínios, fonte/data/confiança, dedup e cache |
| Módulo | IntelScope / ThreatPulse |
| Implementação | Adaptadores planejados |
| Dependências | APIs oficiais opcionais, cache verificável |
| Sistema operacional | Multiplataforma |
| Rede | Online para enriquecimento; offline para cache futuro |
| Licenciamento | Não determinada; verificar edição/versão/API antes de integrar |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Sem contas pagas obrigatórias; dados públicos não são automaticamente corretos |
| Testes necessários / disponíveis | Proveniência, frescor, quotas e falsos positivos necessários |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Não iniciada · M0 |
| Prioridade | P2 |

## graph — RiskGraph / ShieldScore

| Campo | Registro |
|---|---|
| Ferramenta de referência | CVSS, contexto de exposição |
| Problema | Relacionar e priorizar evidências |
| Funcionalidades desejadas / recorte | Grafo dos registros reais por organização: ativos, últimas análises, achados, incidentes e evidências |
| Módulo | RiskGraph / ShieldScore |
| Implementação | Nativa |
| Dependências | Modelo relacional e fatos rastreáveis |
| Sistema operacional | Multiplataforma |
| Rede | Não |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Até200nós/500arestas; sem inferência de caminho explorável. Importação/forense referenciadas por evidências, sem nós próprios |
| Testes necessários / disponíveis | 5 testes de escopo, relações, truncamento, risco e determinismo; UI no roteiro de navegador |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Limitada · M3 |
| Prioridade | P1 |

## crypto — CryptoGuard / TrustGuard

| Campo | Registro |
|---|---|
| Ferramenta de referência | Bibliotecas criptográficas consolidadas |
| Problema | Avaliar uso criptográfico |
| Funcionalidades desejadas / recorte | Regras TLS inseguro/chaves; certificados/cadeias/protocolos futuros |
| Módulo | CryptoGuard / TrustGuard |
| Implementação | Nativa + futuras bibliotecas |
| Dependências | Node crypto, Argon2, rustls |
| Sistema operacional | Multiplataforma |
| Rede | Offline para arquivos; TLS ativo requer rede |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não é auditoria de certificados ou algoritmos completa |
| Testes necessários / disponíveis | Core baseline e auth integration |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Limitada · M3 |
| Prioridade | P2 |

## identity — IdentityGuard

| Campo | Registro |
|---|---|
| Ferramenta de referência | IAM, Active Directory, LDAP |
| Problema | Auditar exportação de identidades |
| Funcionalidades desejadas / recorte | Contas privilegiadas, MFA e estados via JSON; LDAP/AD futuros |
| Módulo | IdentityGuard |
| Implementação | Nativa; adaptadores futuros |
| Dependências | Export sentinel.identity.v1 |
| Sistema operacional | Multiplataforma para arquivo |
| Rede | Não para importação |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não conecta LDAP/AD, não altera identidades externas |
| Testes necessários / disponíveis | packages/core/test/analysis.test.ts |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P2 |

## cloud — CloudShield

| Campo | Registro |
|---|---|
| Ferramenta de referência | AWS/Azure/GCP/Kubernetes; scanners IaC |
| Problema | Examinar políticas exportadas |
| Funcionalidades desejadas / recorte | IAM wildcard e configuração de armazenamento; infraestrutura futura |
| Módulo | CloudShield |
| Implementação | Nativa; adaptadores futuros |
| Dependências | JSON IAM/S3 fornecido |
| Sistema operacional | Multiplataforma |
| Rede | Não para importação |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Sem inventário cloud ativo; não simula toda semântica IAM/SCP |
| Testes necessários / disponíveis | packages/core/test/analysis.test.ts |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P2 |

## ai — SecureBuild / AI & Agent Security

| Campo | Registro |
|---|---|
| Ferramenta de referência | OWASP GenAI Security |
| Problema | Revisar configuração de agentes IA |
| Funcionalidades desejadas / recorte | Permissões de ferramentas, aprovação, dados e limites em export |
| Módulo | SecureBuild / AI & Agent Security |
| Implementação | Nativa |
| Dependências | Export sentinel.ai.v1 |
| Sistema operacional | Multiplataforma |
| Rede | Não |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não é teste de modelo, prompt injection real ou assistente IA operacional |
| Testes necessários / disponíveis | packages/core/test/analysis.test.ts |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P2 |

## ai-assistant — Assistente Sentinel

| Campo | Registro |
|---|---|
| Ferramenta de referência | Provedores/modelos a avaliar |
| Problema | Apoiar explicação e recomendação |
| Funcionalidades desejadas / recorte | Modelos locais/opcionais, evidências, hipóteses, PolicyGate |
| Módulo | Assistente Sentinel |
| Implementação | Planejada |
| Dependências | Modelo compatível com 16GB RAM/GTX1050 |
| Sistema operacional | Conforme runtime |
| Rede | Offline local; online provedor opcional |
| Licenciamento | Não determinada; verificar edição/versão/API antes de integrar |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não conceder administração irrestrita nem tornar API paga obrigatória |
| Testes necessários / disponíveis | Fidelidade às evidências e resistência a instruções em dados necessárias |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Não iniciada · M0 |
| Prioridade | P3 |

## barriers — BarrierMatrix / CanaryWatch

| Campo | Registro |
|---|---|
| Ferramenta de referência | Arquitetura em camadas |
| Problema | Registrar defesa em profundidade |
| Funcionalidades desejadas / recorte | 14 camadas, controles, evidências e estado observado |
| Módulo | BarrierMatrix / CanaryWatch |
| Implementação | Nativa parcial |
| Dependências | Resultados de motores |
| Sistema operacional | Multiplataforma |
| Rede | Não |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Camada só cadastrada não protege; canários e controles ativos pendentes |
| Testes necessários / disponíveis | packages/core/test/core.test.ts |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Limitada · M3 |
| Prioridade | P1 |

## evidence — EvidenceChain

| Campo | Registro |
|---|---|
| Ferramenta de referência | Práticas de cadeia de custódia |
| Problema | Preservar originais e rastreabilidade |
| Funcionalidades desejadas / recorte | AES-GCM, SHA256, append-only, acesso auditado e vínculos |
| Módulo | EvidenceChain |
| Implementação | Nativa + primitivas mantidas |
| Dependências | PostgreSQL e chave externa |
| Sistema operacional | Multiplataforma |
| Rede | Não |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Hash não garante cadeia inteira; administrador de banco pode adulterar; retenção e exportações ampliadas pendentes; cadeia completa por operação/teste/observação/reteste e comparação ainda pendentes, conforme plano AttackLab |
| Testes necessários / disponíveis | API evidence/audit tests e restore anterior |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Limitada · M3 |
| Prioridade | P0 |

## reports — Reporting Engine

| Campo | Registro |
|---|---|
| Ferramenta de referência | Relatórios profissionais citados no V6.6 |
| Problema | Documentar resultados verificáveis |
| Funcionalidades desejadas / recorte | JSON scan/risco; relatórios de módulos e incidentes em evolução |
| Módulo | Reporting Engine |
| Implementação | Nativa |
| Dependências | Dados de projeto/escopo/evidência |
| Sistema operacional | Multiplataforma |
| Rede | Não |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Relatórios JSON de análises, incidentes, forense e importação; PDF e comparação generalizada pendentes |
| Testes necessários / disponíveis | API scan report tests |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Limitada · M3 |
| Prioridade | P1 |

## integrations — Integration Framework

| Campo | Registro |
|---|---|
| Ferramenta de referência | Tipos Native/OSS/External/OS/Lab/Commercial |
| Problema | Declarar contratos e dependências externas |
| Funcionalidades desejadas / recorte | Adaptadores Python forense/importação e Nmap limitado; contratos e limites específicos |
| Módulo | Integration Framework |
| Implementação | Nativa planejada |
| Dependências | Matriz versionada e registro de adaptadores |
| Sistema operacional | Multiplataforma |
| Rede | Conforme adaptador |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não há carregamento arbitrário de plugins nem catálogo universal. Versão Nmap real não homologada |
| Testes necessários / disponíveis | Catálogo conferido com arquivos e registros desta sessão |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Parcialmente implementado · M2 |
| Prioridade | P1 |

## validation — Validation Lab / Backup Recovery

| Campo | Registro |
|---|---|
| Ferramenta de referência | Testes do projeto |
| Problema | Comprovar fluxos e recuperação |
| Funcionalidades desejadas / recorte | Unit/API/browser, Rust/Python, restore, isolamento |
| Módulo | Validation Lab / Backup Recovery |
| Implementação | Nativa |
| Dependências | Runtimes e fixtures sintéticas |
| Sistema operacional | Windows executado; Debian pendente |
| Rede | Não para testes locais |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Testes de novas alterações não promovem operação Debian; avaliação independente ausente |
| Testes necessários / disponíveis | docs/VALIDATION.md histórico; relatório desta alteração pendente |
| Evidências | Código, casos automatizados e resultados registrados; itens pendentes não são prova de operação. |
| Estado real | Integrada · M3 |
| Prioridade | P0 |

## import-zip — Universal Import Lab

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Inspeção de projetos autorizados antes da avaliação |
| Funcionalidades desejadas / recorte | ZIP em quarentena cifrada, hashes, inventário e tecnologias indicativas, projeto herdado do ativo |
| Módulo | Universal Import Lab |
| Implementação | Nativa |
| Dependências | Python3.11+, PostgreSQL |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Sem extrair/executar;16MiB/512entradas/64MiBexpandidos;semZIP64,descritores,nestedarchives;12testesworker+6API |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P0 |

## forensic-worker — NetworkTrace / DeepTrace / MobileScope

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Analisar capturas e backups fornecidos |
| Funcionalidades desejadas / recorte | PCAP/PCAPNG, SQLite e plist offline com hash antes/depois e relatório |
| Módulo | NetworkTrace / DeepTrace / MobileScope |
| Implementação | Nativa |
| Dependências | Python3.11+ |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Sem aquisição de dispositivo/imagem;semTLSdecrypt;SQLitevaloresomitidos;16testesworker+5API |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P1 |

## url-git-import — Web URL Importer / Git Importer

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Trazer sites e fontes autorizadas |
| Funcionalidades desejadas / recorte | Adaptadores com SSRF, redirecionamentos, resolução/endereço fixado e credenciais temporárias |
| Módulo | Web URL Importer / Git Importer |
| Implementação | Nativa |
| Dependências | A definir |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não implementado; URLs públicas não autorizam teste |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Não iniciado · M0 |
| Prioridade | P0 |

## authorization-manager — Authorization Manager

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Registrar autoridade e limites de teste |
| Funcionalidades desejadas / recorte | Responsável e comprovação cifrados, projeto/ativos, rascunho imutável, revisão, aprovação, vigência, risco, nove perfis e limites por entrada |
| Módulo | Authorization Manager |
| Implementação | Nativa |
| Dependências | PostgreSQL/PolicyGate |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Administrador cria/aprova/revoga; analista consulta detalhes. Ativo gerenciado não admite retorno ao legado; troca de limites exige novo rascunho |
| Limitações | Somente executores implementados; bytes por entrada e portas explícitas. Sem cota acumulada, remediação do host, cancelamento imediato ou verificação jurídica automática; falta manifesto revisado de endereços e exclusões para operações AttackLab |
| Testes necessários / disponíveis | 13 testes de política e20 de API passaram; API também passou no PostgreSQL restrito. Navegador e restore36 tabelas/9migrações validados no Windows |
| Evidências | Migração009, authorization-manager.ts, policy.ts, AuthorizationView e VALIDATION_REPORT.md |
| Estado real | Parcialmente implementado · M3 |
| Prioridade | P0 |

## prooflab — ProofLab / Before-After Comparison

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Demonstrar correção com reteste comparável |
| Funcionalidades desejadas / recorte | Aplicação vulnerável isolada integrada a importação, avaliação, correção e relatório |
| Módulo | ProofLab / Before-After Comparison |
| Implementação | Nativa |
| Dependências | Isolamento de laboratório a validar |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | SecureFixdeconfiguraçãoérecorteexistente;aplicaçãoProofLabcompletanãoimplementada |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Não iniciado · M0 |
| Prioridade | P0 |

## assessment — Security Assessments

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Planejar e acompanhar testes de uma aplicação |
| Funcionalidades desejadas / recorte | Plano versionado, catálogo de testes, execução e reteste |
| Módulo | Security Assessments |
| Implementação | Nativa |
| Dependências | PolicyGate/importação/jobs |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Analisadores existentes não equivalem ao fluxo central completo |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Não iniciado · M0 |
| Prioridade | P0 |

## execution-center — Execution Center

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Orquestrar trabalhos persistentes |
| Funcionalidades desejadas / recorte | Jobs básicos existentes; fila, prioridades, aprovação, cancelamento e CLI unificada pendentes |
| Módulo | Execution Center |
| Implementação | Nativa |
| Dependências | PostgreSQL |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Estados atuais running/completed/failed/interrupted; não cobre todos estadosV6.9 |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Parcialmente implementado · M2 |
| Prioridade | P0 |

## resilience — ResilienceLab

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Medir disponibilidade e recuperação sob carga autorizada |
| Funcionalidades desejadas / recorte | Cargas limitadas com interrupção e métricas, k6/Locust opcionais |
| Módulo | ResilienceLab |
| Implementação | Nativa |
| Dependências | Laboratórioisolado |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não implementado nem executado |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Não iniciado · M0 |
| Prioridade | P2 |

## iot-ot — IoT Security / OT-ICS Security

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Avaliar dispositivos e ambientes industriais autorizados |
| Funcionalidades desejadas / recorte | Inventário passivo, firmware, segmentação e risco operacional |
| Módulo | IoT Security / OT-ICS Security |
| Implementação | Nativa |
| Dependências | Ambientesdedicados |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Sem protocolo industrial ativo ou testes de disponibilidade implementados |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Não iniciado · M0 |
| Prioridade | P2 |

## privacy-grc — Privacy / Governance / GRC

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Gerenciar risco, dados e evidências de governança |
| Funcionalidades desejadas / recorte | Registro de riscos, minimização/retenção, controles e auditoria |
| Módulo | Privacy / Governance / GRC |
| Implementação | Nativa |
| Dependências | Processos/referênciasconfiguráveis |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Auditoria técnica existente não constitui conformidade ou certificação |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Não iniciado · M0 |
| Prioridade | P2 |

## continuity — Business Continuity

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Vincular recuperação às necessidades dos serviços |
| Funcionalidades desejadas / recorte | BIA, RTO/RPO, planos e exercícios |
| Módulo | Business Continuity |
| Implementação | Nativa |
| Dependências | Backup/restorebase |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Teste de restauração técnica não constitui BIA/DR empresarial completo |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Não iniciado · M0 |
| Prioridade | P2 |

## human — Human Security

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Treinar e acompanhar conscientização |
| Funcionalidades desejadas / recorte | Trilhas e exercícios autorizados com privacidade |
| Módulo | Human Security |
| Implementação | Nativa |
| Dependências | A definir |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Não implementado;nenhum envio de simulação realizado |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Não iniciado · M0 |
| Prioridade | P2 |

## third-party — Third-Party Risk

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Acompanhar riscos de fornecedores |
| Funcionalidades desejadas / recorte | Inventário e avaliações de fornecedores integrados a SBOM |
| Módulo | Third-Party Risk |
| Implementação | Nativa |
| Dependências | A definir |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Análise de lockfile não equivale à gestão de terceiros |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Não iniciado · M0 |
| Prioridade | P2 |

## services — Security Services / Managed Security

| Campo | Registro |
|---|---|
| Ferramenta de referência | Especificação V6.9; detalhes nos guias do módulo |
| Problema | Organizar prestação de serviços por cliente |
| Funcionalidades desejadas / recorte | Catálogo, entregas, equipes e acompanhamento recorrente |
| Módulo | Security Services / Managed Security |
| Implementação | Nativa |
| Dependências | Clientes/projetos/relatórios |
| Sistema operacional | Multiplataforma |
| Rede | Sem rede durante inspeção offline; futuras integrações conforme escopo |
| Licenciamento | Código Sentinel proprietário; dependências no inventário de licenças; ferramentas de referência não embutidas |
| Autorização | Operador autenticado; isolamento de empresa/projeto. Análise/ingestão requer escopo de ativo; dados e alvos devem ser próprios ou autorizados. |
| Limitações | Operadorúnico;nenhumrecurso liberado comercialmente |
| Testes necessários / disponíveis | Ver TESTING.md e VALIDATION_REPORT.md; não há teste de comportamento ainda não implementado |
| Evidências | Código e evidências de testes somente para o recorte implementado; limitações explícitas. |
| Estado real | Não iniciado · M0 |
| Prioridade | P2 |
