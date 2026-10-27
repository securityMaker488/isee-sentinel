# I.See Sentinel — guia mestre consolidado

**Proprietária:** I.See Technologies · **Divisão:** I.See Cybersecurity.
**Consolidação:** 27/10/2026 · **Base funcional:** V6.9, com requisitos compatíveis
de V5.0, V6.3, V6.5 e V6.6, complemento multiplataforma e complemento AttackLab
Evidence Fusion & Purple Validation Engine.

Este é o ponto único de consulta dos **requisitos de desenvolvimento**. O estado
mutável e o ponto exato de retomada ficam em [PROJECT_STATE.md](../PROJECT_STATE.md);
a fila fica em [ROADMAP.md](../ROADMAP.md). Os originais preservam a proveniência,
mas não constituem filas concorrentes. [PROMPT-COVERAGE.json](PROMPT-COVERAGE.json)
registra fontes, hashes, índice das seções e correspondência temática. G26
registra decisões de precedência; o índice não é percentual de implementação.

## G01 — Continuidade, precedência e definição do trabalho

Ao receber “continue o que estava fazendo”:

1. Ler `AGENTS.md`, o checkpoint de `PROJECT_STATE.md` e a tarefa da fila.
2. Conferir alterações locais, último commit e processos temporários pertinentes.
3. Inspecionar apenas os arquivos afetados e suas dependências necessárias;
   preservar auditorias válidas e código funcional. Corrigir erros encontrados.
4. Concluir o menor incremento funcional, integrado e verificável, respeitando
   dependências. Não saltar fases, reiniciar o produto ou preencher menus vazios.
5. Executar testes relevantes, registrar ambiente/revisão/resultados/limites e
   atualizar o checkpoint com a próxima ação concreta antes de encerrar.

Uma evolução de prompt acrescenta requisitos; não apaga o progresso. A instrução
mais recente do operador prevalece. A V6.9 governa a sequência global 0–12; o
complemento AttackLab detalha seis fases internas. O complemento multiplataforma
governa continuidade, Git e reprodução de ambiente. Detalhes compatíveis antigos
continuam neste guia. As numerações V6.5 0–10 e V6.6 0–16 são históricas.

“Inspecionar todos os arquivos antes de modificar”, nos prompts iniciais, já foi
tratado na auditoria do projeto. Não exige repetir auditoria integral a cada
continuação: a preferência posterior do operador determina revisão dirigida.
Um novo requisito exige conferir suas interfaces reais, sem presumir implementação.

Concluir primeiro o trabalho possível no Windows. Debian será a etapa de
homologação de capacidades dependentes do Linux; não usar sua ausência para adiar
contratos, parsers, APIs, UI ou testes portáteis. Instalar Debian não conclui o
produto. “100%” é objetivo do operador, nunca status presumido.

## G02 — Missão, propriedade, princípios e modelo de uso

Construir uma plataforma integrada para:
**Importar → Identificar → Investigar → Auditar → Testar → Demonstrar → Detectar →
Proteger → Corrigir → Retestar → Comparar → Recuperar → Documentar → Monitorar.**
O diferencial próprio reúne orquestração, dados, políticas, correlação, experiência,
evidências e métodos da I.See; não depende de reinventar criptografia ou copiar
código fechado. Utilizar bibliotecas maduras e integrações legais quando adequadas.

Aplicar Security/Privacy by Design, Zero Trust, defesa em profundidade, defaults
seguros, menor privilégio, separação de responsabilidades, negação segura,
evidências, reprodução, prioridade a tecnologias abertas, operação local/offline,
modularidade, automação controlada, participação humana, resiliência, cadeia de
suprimentos segura, verificação contínua e validação independente.

A edição inicial é **Private Operator Edition**: um fundador administrativo,
clientes como organizações/projetos, sem acesso deles ao painel. Manter MFA,
sessões protegidas, recuperação administrativa segura, controle de recursos e
identidades de serviço separadas mesmo com um operador. Sem credenciais padrão.
Passkeys/WebAuthn são preferência futura quando viáveis, não capacidade presumida.
Não antecipar cadastro público, convites, portal, marketplace, cobrança, planos,
assinaturas ou SaaS. Equipes, licenciamento e MSSP/MDR são evolução posterior.

Adotar perspectivas de arquitetura, Rust/TypeScript/Python, Linux/Windows, banco,
frontend/backend, DevSecOps/SRE/QA, AppSec/API, Red/Blue/Purple, SOC/detecção/hunting,
forense/malware, cloud/identidade/Zero Trust, mobile/IoT/OT/IA/criptografia,
GRC/privacidade/continuidade, consultoria e entrega de serviços. São perspectivas
técnicas, não uma alegação de profissionais reais participando. Avaliar custo,
manutenção, compatibilidade, desempenho, licenças e viabilidade em cada decisão.

Não prometer segurança absoluta, recuperação de dados impossível, detecção perfeita,
equivalência comercial, certificação ou liberação profissional sem evidência.

## G03 — Arquitetura, tecnologias e fronteiras

Manter o monorepositório privado `isee-sentinel` e reutilizar seus componentes:

| Componente | Responsabilidade e regra |
|---|---|
| `apps/web` | React/TypeScript, Vite e Tailwind; interface acessível em português, navegador moderno, consultas tipadas e contexto explícito de empresa/projeto |
| `apps/api` | Node.js LTS compatível, Fastify/TypeScript, REST/OpenAPI, autenticação, autorização, contratos, orquestração, auditoria e PostgreSQL |
| `packages/core` | Motores determinísticos tipados e versionados; sem subprocesso, disco/rede ou execução de conteúdo analisado |
| `packages/endpoint-agent` | Rust, APIs nativas, telemetria autorizada, integridade, supervisão e comunicação autenticada; adaptadores distintos por SO |
| `workers` | Python em ambientes isolados, processamento especializado e ferramentas por adaptadores; entradas explícitas, limites e preservação de originais |
| Persistência | PostgreSQL local administrado para operação; PGlite somente desenvolvimento/testes explícitos, migrações imutáveis após aplicação, checksums e runtime restrito |
| Infraestrutura | Debian 13 Stable/KDE, systemd quando necessário, Git, backups, QEMU/KVM, libvirt/virt-manager e Kali sob demanda |

Organizar responsabilidades em seis planos lógicos: **Control Plane** (identidade,
clientes/ativos/políticas), **Security Data Plane** (eventos/telemetria/histórico),
**Analysis Plane** (código/configuração/perícia/rede/inteligência), **Defense Plane**
(detecção/contenção/correção/recuperação), **Laboratory Plane** (ambientes isolados)
e **Intelligence Plane** (assistência contextual sem autoridade irrestrita).
Isso não exige seis serviços residentes nem reescrita do monorepo.

Evitar dependências circulares e acesso direto indiscriminado entre módulos.
Toda comunicação deve definir API/esquema, autenticação de serviço, autorização,
versão, eventos, erros, timeout, cancelamento, retries, idempotência, limites,
logs e recuperação. Não substituir tecnologias validadas sem justificativa.

## G04 — Windows, Debian, hardware e operação econômica

Ambiente inicial: Windows 10 Pro disponível. Principal futuro: Debian 13 Stable
com KDE Plasma. Compatibilidade adicional Windows 11/Ubuntu/outras distribuições
é progressiva; Windows 10 exige compatibilidade e suporte de segurança adequados.
Não declarar suporte completo antes dos testes. Isolar journald/Linux Audit e
systemd dos adaptadores Windows Event Log/ETW/serviços/APIs oficiais.

Hardware declarado historicamente: aproximadamente 16 GB RAM, GTX 1050/4 GB VRAM,
SSD Kingston A400/480 GB e HD externo de 1 TB. São declarações, não medição atual.
Diagnosticar CPU, armazenamento, drivers e folga antes de dimensionar. Não exigir
GPU dedicada; não instalar drivers NVIDIA ou misturar repositórios arbitrariamente.

Arquitetura híbrida: Debian nativo para núcleo; Podman rootless **opcional** para
workers leves e testes descartáveis; Kali em VM para cenários que exigem kernel
próprio. Hipótese inicial Kali: 2 vCPUs, 4 GB RAM, disco expansível 40–60 GB, a
confirmar. Desligar quando ociosa; não instalar serviços pesados permanentes nela.

Usar carregamento seletivo, serviços sob demanda, jobs assíncronos, cotas de
CPU/RAM/disco, retenção e monitoramento. SSD para trabalho ativo/banco; disco
externo pode guardar backups/ISOs/snapshots/datasets/exportações após identificação
e autorização. Nunca deixar nele a única cópia importante. Não formatar, montar
para escrita ou alterar partições, boot, firmware, Windows ou serviço preexistente
sem autorização específica. A escolha antiga de Arch foi substituída por Debian.

Sem Docker, Kubernetes, Redis, Firebase, Supabase, VPS, cloud ou API paga
obrigatórios. Núcleo local/offline nas capacidades compatíveis. Declarar rede
necessária para instalação/atualização, feeds, ativos remotos e APIs opcionais.
Cache de inteligência contém origem, versão, integridade, data e aviso de
desatualização. Não apresentar dados antigos como inteligência atual.

## G05 — Clientes, autorização e PolicyGate

Cadastrar organização, projeto, contrato, responsável, ativo, serviço, aplicação,
domínio/IP/rede autorizados, avaliações, incidentes, evidências, correções,
aprovações, retestes e relatórios. Isolar clientes em banco, consultas, caches,
arquivos, logs e exportações; controles no backend, não só na interface.

Reutilizar **Authorization Manager** para responsável e evidência de autoridade
(documento, contrato, e-mail ou WhatsApp fornecido legitimamente), finalidade,
cliente/laboratório, projeto, ativos incluídos e excluídos, testes/perfis, modo,
risco, restrições, janela, limites, aprovação e histórico. Conversa informal não
autoriza qualquer teste disruptivo. Aprovação de um conjunto de testes previamente
definido pode servir ao projeto; mudança material exige nova revisão.

O **PolicyGate determinístico** verifica identidade/papel, organização/projeto,
ativo/alvo exato, operação, ambiente, contrato/escopo, horário, risco, limites e
aprovação antes de preparar e executar. Todos os agentes, ferramentas, CLI e IA
passam por ele. Negar por padrão. Estar na rede, ser privado/loopback ou público
na internet não comprova autorização. Exclusões prevalecem sobre inclusões.

Manter termos imutáveis vinculados a hash revisado, comprovação protegida,
expiração automática, revogação e cancelamento emergencial supervisionado.
Revalidar mandato, alvo e parâmetros antes de despacho. Não atribuir autorização
retroativa a resultados antigos. Revogar permissão e interromper processo são
capacidades distintas, ambas necessitam implementação e teste.

Modos visíveis: **LAB** (próprio/isolado), **ASSESSMENT** (sistemas reais e limites
contratuais) e **PRODUCTION REMEDIATION** (backup, teste, revisão, aprovação
específica, rollback e verificação). Níveis de autonomia: 0 observação; 1
recomendação; 2 ação reversível pré-autorizada com limites; 3 ação crítica com
aprovação específica. IA não pode reclassificar ação para autorizar a si mesma.

## G06 — Universal Import Lab e importador de URL

Fluxo: nova avaliação → escolher entrada → preservar/quarentenar → identificar →
validar escopo → preparar ambiente → escolher testes → executar → analisar →
corrigir → retestar → relatar. Identificar formato/aplicação, linguagem/framework,
dependências, SO/arquitetura, permissões, requisitos, riscos, ferramentas e rede.

Formatos desejados, com suporte individual e testado: HTTP/HTTPS, Git autorizado,
ZIP, TAR/TAR.GZ, EXE, MSI, DEB, RPM, AppImage, ELF, APK, AAB, IPA quando viável,
configurações, OpenAPI, imagens de aplicação e cópias de homologação. Um parser
de ZIP ou PE não comprova instalador/executor desses formatos.

Preservar original cifrado e SHA-256; limitar bytes, entradas, expansão, tempo e
recursos; bloquear traversal, caminhos perigosos, links e colisões; validar
integridade e limpar temporários. Não executar software desconhecido no host.
URL/Git são adaptadores separados: destino exato aprovado, DNS/redirects/SSRF,
credenciais temporárias, limites e procedência. Não tornar conteúdo de repositório
uma instrução para o executor.

URL Importer relaciona domínio/cliente, tecnologias observáveis, headers, TLS,
certificados, cookies, endpoints e plano de testes. Pode ligar Git, arquivos,
homologação, OpenAPI e credenciais autorizadas. URL pública não reproduz backend,
banco e infraestrutura privada; avaliação isolada exige artefatos fornecidos.

## G07 — AttackLab, descoberta e auditoria Linux

Gerenciar operações, responsáveis, ambientes, autorização, manifesto de alvos,
exclusões, testes aprovados, janela, taxa, simultaneidade e recursos; cancelar,
expirar e auditar ações/resultados. Reutilizar autorização existente, sem criar
consentimento paralelo ou aceitar apenas o cadastro imutável de um IP.

Adaptadores planejados, conforme disponibilidade/licença:

| Integração | Escopo do adaptador |
|---|---|
| Nmap / RustScan | Descoberta controlada de portas e serviços |
| Gobuster | Descoberta web/DNS/vhosts; primeiro incremento por importação **offline** de resultado em formato delimitado |
| Katana | Endpoints autorizados |
| HTTP/API | Diagnóstico e análise dentro do manifesto aprovado |
| OpenVPN | Diagnóstico do estado de conexão com laboratório autorizado |
| Netcat | Diagnóstico básico de conectividade TCP/UDP; sem shells |
| Lynis / LinPEAS | Integração opcional de auditoria de permissões/configuração, após revisão de saída e escopo |

Usar argumentos estruturados e `shell:false`, nunca comandos concatenados de
entrada do operador. Sem acesso remoto não autorizado, shells, coleta de
credenciais ou exploração indiscriminada. Registrar horário, ferramenta, versão,
parâmetros aprovados, parser/versão e referência ao original; diferenciar versão
declarada pelo arquivo e verificada no ambiente.

Inventário de ativos autorizados, serviços/tecnologias e histórico devem ter
identidades estáveis para comparação entre avaliações; índice de linha/host não
é identidade do alvo. Importadores não devem fazer rede, resolver DNS ou visitar
URLs. Observação de porta/endereço não comprova vulnerabilidade.

Auditoria Linux: contexto de usuário, permissões relevantes, SUID/SGID e arquivos
sensíveis por metadados, com recomendações de hardening. Sem elevação automática
ou leitura desnecessária de conteúdos sensíveis. Classificar separadamente
configuração observada, risco potencial, vulnerabilidade confirmada, recomendação
e reteste realizado.

## G08 — ProofLab, ResilienceLab e isolamento

**ProofLab:** aplicação vulnerável própria ou integração adequada com Juice Shop/
WebGoat → vulnerabilidade escolhida → teste reproduzível → evidência/impacto →
patch em cópia → reteste comparável → antes/depois → relatório identificado como
laboratório. O cenário SOC sintético não encerra sozinho essa entrega.

**ResilienceLab:** carga, stress, spike, soak, capacidade, rate limiting,
recuperação, latência, erros, CPU/RAM e gargalos de banco; k6/Locust opcionais.
Exigir duração, tráfego, recursos e interrupção. Cenários disruptivos em
homologação/laboratório autorizado; não disponibilizar DDoS indiscriminado.

Classificar risco: A estudos/código benigno; B simulações controladas em sistemas
vulneráveis; C amostras não confiáveis com isolamento reforçado. VMs descartáveis,
snapshots e restauração, saídas controladas, cotas, monitoramento, limpeza e
compartilhamentos mínimos são necessários conforme risco. Contêiner/chroot não
substituem kernel isolado e VM convencional não é contenção infalível de malware.

Perfis de rede: **Isolated**, **Restricted**, **Authorized Assessment** e
**Production Remediation**. Validar rotas, DNS, interfaces, firewall,
redirecionamentos, host/guest e rede doméstica/clientes antes de habilitar cenário.
Libvirt sem internet ainda pode alcançar serviços do Debian host; isso não basta
como isolamento. Separar rede de atualização da rede de testes; desabilitar
compartilhamentos desnecessários. Podman, quando usado, é rootless, sem
`--privileged`, com imagem confiável/versionada, montagens/rede mínimas e limites
efetivamente verificados.

## G09 — EvidenceChain, Evidence Fusion, RiskGraph e comparação

Relação verificável: **Operação autorizada → Ativo → Teste → Observação → Evidência
→ Alerta → Achado → Correção → Reteste**. Acrescentar empresa/projeto, serviço,
tecnologia, identidade/permissão, aplicação/dependência, incidente, indicador,
controle e risco quando existirem vínculos reais.

Evidência contém ID, caso/operação, organização/projeto, fonte, ferramenta/versão,
operador/processo, timestamps/fuso, tipo, SHA-256, armazenamento, integridade,
histórico de acesso/transferência/transformação, achados e observações. Preservar
originais e derivar cópias de análise separadamente. Hash isolado não garante
toda a cadeia de custódia. Proteger dados sensíveis, acessos, retenção, exportação
e histórico contra alteração indevida; verificar integridade ao processar.

Timeline e grafo devem apresentar proveniência e limites/paginação, consultar por
operação e não misturar organizações. Não inferir caminho explorável por mera
relação gráfica. Comparar alvos/serviços/métodos/entradas compatíveis, distinguir
tempo declarado, recebimento e execução comprovada. Ausência em arquivo parcial
ou desaparecimento do scanner não confirma correção.

Antes/depois inclui falhas confirmadamente corrigidas, persistentes e novas,
mudanças, testes, evidências e riscos residuais. Reteste tem execução própria e
referência à avaliação anterior. RiskGraph prioriza por impacto, exposição,
criticidade, confiança, exploração conhecida, controles compensatórios e contexto
de negócio; CVSS/EPSS quando cabíveis, metodologia explicável e sem percentuais
inventados de proteção.

## G10 — SOC, Blue Detection Fusion e Purple Validation

SOC/DefenseFlow/Detection Engine: ingestão, normalização, deduplicação,
enriquecimento, correlação temporal/comportamental, regras versionadas, alertas,
triagem, casos, incidentes, investigação, hunting, timeline, métricas, histórico,
evidências, revisão de falsos positivos e regressões de regras.

Integrar progressivamente Suricata, Sigma, YARA, Auditd, logs do SO e agente local;
avaliar Zeek, Wazuh e OpenTelemetry sem dependência de SIEM comercial. Evento
comum inclui esquema/ID, origem, horário, host/ativo, categoria/técnica observada,
severidade/classificação/confiança, contexto, empresa/projeto e evidência. Toda
transformação preserva origem. Mapear MITRE ATT&CK somente com justificativa e
versão. Alerta não é invasão confirmada sem evidência suficiente.

**PurpleMatrix/Purple Validation:** catálogo de cenários, importação validada de
metadados Atomic Red Team/MITRE, requisitos, risco e regra de detecção associada;
primeiro registrar resultados manuais autorizados, atividade esperada e alertas
observados. Importação de definição não executa seus comandos. Automação
potencialmente destrutiva permanece desabilitada por padrão e requer aprovação,
isolamento comprovado e controles próprios implementados.

Ciclo Purple: técnica/objetivo defensivo → cenário → execução autorizada →
telemetria → detecção → lacunas → ajuste → reteste → relatório comparativo.
Medir cenários/técnicas realmente testados, alertas esperados/encontrados, lacunas,
melhorias e retestes; declarar denominador/período/fontes. Não inferir cobertura
global de MITRE ou eficácia não testada.

## G11 — Agentes, BarrierMatrix e motores complementares

Agentes Rust Linux/Windows coletam somente telemetria autorizada: processos,
serviços, arquivos/integridade, autenticação, metadados de conexões e eventos de
segurança por APIs nativas. Comunicação autenticada, identidades de serviço,
replay/idempotência, autorização/revogação, baseline aprovada, limites e remoção
legítima. Sem agente clandestino, shell remoto ou autopersistência silenciosa.
SIEM/EDR/XDR são objetivos progressivos: um coletor não comprova EDR completo;
correlação entre endpoint/aplicação/identidade/rede/cloud exige integração real.

Cada controle BarrierMatrix registra ID, objetivo, ativo, ameaça, configuração,
dependência, política, estado/saúde, risco, evidência, teste/cobertura, histórico,
responsável, limites e recuperação. Cadastro ou avaliação estática não significa
controle ativo.

| Camada | Requisitos preservados |
|---|---|
| 1 Edge Protection | WAF/filtragem HTTP, rate limiting/conexões, abuso de login/bots, bloqueio temporário e reputação com revisão; CDN/mitigação upstream opcional, sem promessa de conter DDoS volumétrico localmente |
| 2 Network Security | Segmentação administrativa/serviços, firewall entrada/saída, deny-by-default, portas, exposição, túneis, acesso administrativo, movimento lateral/DNS e desvios da política |
| 3 Identity Security | MFA/passkeys viáveis, RBAC/ABAC por recurso, sessões/revogação/reautenticação sensível, menor privilégio, elevação temporária autorizada e identidade de serviço |
| 4 Application Security | SQL/command injection, XSS/CSRF/SSRF, traversal/uploads, mass assignment, IDOR/BOLA, desserialização, sessões/dados/lógica/API; WAF não substitui correção |
| 5 Database Security | Credenciais por serviço, consultas parametrizadas, runtime mínimo, conexões, migrações, acesso/isolamento, RLS quando aplicável, auditoria, retenção/mascaramento e restore |
| 6 Cryptography & Secrets | TLS/certificados, Argon2id apropriado, tokens seguros, gestão/rotação de chaves, ambientes separados, proteção em repouso/trânsito e ausência de segredos em logs |
| 7 Endpoint & Server Security | Atualizações, serviços, SSH/firewall/permissões, FIM, autenticação, processos/execuções, contas administrativas, baseline e desvios |
| 8 Software Supply Chain | SBOM, dependências transitivas/CVEs/segredos, procedência/integridade, versões/build/CI/CD, permissões de pipelines e atualização validada |
| 9 AI Agent Security | Prompt injection direta/indireta, dados/ferramentas/autonomia, arquivos, credenciais, permissões, respostas, RAG/base de conhecimento, modelos/dependências e recursos |
| 10 Intrusion Detection | Regras/anomalias, correlação/logs/autenticação/FIM/IOCs, triagem/investigação, condições, confiança e evidências |
| 11 Threat Containment | Playbooks para bloqueio temporário, revogação/restrição, isolamento legítimo, regras emergenciais, redução de exposição, preservação e escalonamento; sem retaliação |
| 12 Autonomous Remediation | Patch, teste, versão segura, aprovação, implantação gradual, indicadores, rollback e reavaliação conforme política |
| 13 Resilience & Recovery | Backup/versionamento/snapshot, integridade, restore testado, continuidade, falhas, indisponibilidade, RPO/RTO e cópias protegidas |
| 14 Audit & Forensics | Auditoria/logs, evidências/hashes, timeline/custódia/investigação, retenção, exportação, revisão de acessos e originais |

CanaryWatch: tokens/credenciais fictícias sem privilégios e arquivos-isca internos
com alerta. TrustGuard: postura de sessão/serviço/credenciais/risco e revogação.
IntegrityWatch: integridade de arquivos/configurações/pacotes/regras/políticas.
ShieldScore: método explicável de maturidade (MFA, atualizações, exposição,
inventário, riscos, backup/detecção/recuperação), sem garantia de segurança.
SafeDeploy: pré-verificação, assinatura/integridade quando cabível, aprovação,
implantação gradual, health/monitoramento, rollback e histórico.

## G12 — SecureBuild e avaliações Web/API/infraestrutura

SAST, DAST autorizado, SCA, segredos, SBOM, dependências/licenças/CVEs, IaC,
CI/CD, revisão de código, autenticação/autorização/APIs e software gerado por IA.
Regras tipadas/versionadas, localização, evidência, impacto, severidade, confiança,
referência, correção e reteste. Código fornecido: inventário, linguagens/frameworks,
configurações, entradas/saídas, uploads, dados e permissões. Priorizar código e
configurações legítimos antes de conectores externos.

Catálogo Web progressivo: SQLi, XSS, CSRF, SSRF, command injection, traversal,
file inclusion, XXE, desserialização/upload inseguros, autenticação/autorização,
IDOR/BOLA, elevação de privilégios, dados, CORS, sessões/cookies/JWT, criptografia,
dependências e lógica de negócio. APIs: REST/GraphQL/WebSocket, OpenAPI,
OAuth/JWT, parâmetros, objetos, erros, limites e exposição. Infraestrutura:
inventário/serviços autorizados, configuração, TLS, hardening e segmentação.
Cada teste declara objetivo, pré-requisitos, ambiente, impacto, autorização,
parâmetros/limites, evidências, resultado e possíveis falsos positivos.

Avaliar ZAP, Semgrep (edição/licença), Gitleaks, Trivy, OSV-Scanner e Syft por
adaptadores. Não instalar todos indiscriminadamente. Suporte a sites/APIs,
Node/React/Next.js/Python e outros frameworks segue contratos e testes próprios.

Firebase e Supabase são **alvos externos auditáveis**, nunca infraestrutura
obrigatória do Sentinel. Firebase: regras Firestore/Realtime Database/Storage,
auth, segregação, credenciais administrativas e integrações. Supabase: RLS,
políticas/PostgreSQL/auth/Storage/Edge Functions, service-role, APIs e dados.
Distinguir configuração/chave pública legítima de segredo com poder efetivo.
External Backend Security Adapters podem incluir Firebase, Supabase, AWS/Azure/
Google Cloud, PostgreSQL e MySQL após a base genérica: leitura mínima, segredos
protegidos, escopo, achados verificáveis, RiskGraph/SecureFix e auditoria.

## G13 — Remediation, ResponseGrid, AutoDefense e Self-Healing

Remediation/SecureFix: identificar causa/arquivos → explicar impacto → propor
patch → branch/diff/cópia → testes/regressão/homologação → revisão/aprovação →
aplicação gradual → verificar/retestar → documentar; original e rollback
preservados. Cobrir progressivamente código/dependências, auth, configuração,
API/banco/credenciais/criptografia/rate limiting, servidores/infraestrutura.
Compilar não prova segurança. Produção exige aprovação específica.

ResponseGrid inclui contatos, políticas, runbooks, ativos/backup, triagem,
investigação, impacto, responsáveis, aprovações, contenção, erradicação,
recuperação, comunicação, evidências e lições aprendidas. Apoia documentação
de incidente/notificação; não substitui avaliação jurídica.

AutoDefense: detectar → correlacionar → classificar → investigar → preservar →
avaliar resposta → PolicyGate → conter conforme autorização → plano de correção
→ validar → executar → reavaliar → registrar → monitorar recorrência.
Separar recomendação, ação reversível pré-autorizada e intervenção crítica.

Self-Healing: desvio versus estado aprovado, diagnóstico, serviços, restauração,
integridade, rollback e validação posterior. Limites de tentativas, circuit breaker
e escalonamento humano impedem ciclos infinitos. Não apagar evidências durante
recuperação. Correção/restauração de cópia no banco não equivale a alterar host.

## G14 — Perícia computacional e móvel

**DiskLab/DeepTrace/EvidenceChain:** imagens forenses RAW/DD e E01 quando legal e
tecnicamente disponível; SHA-256, origem/finalidade/operador/ferramenta/versão,
leitura do original, integridade durante processamento. Suporte progressivo
NTFS/FAT32/exFAT/ext4: diretórios, metadados/permissões/timestamps, ocultos,
assinatura versus extensão, artefatos excluídos recuperáveis, busca por hash/texto,
logs/navegação legitimamente importada/recentes/persistência e timeline.
Inventário, achados referenciados e exportação verificável. Avaliar TSK/Autopsy;
FTK/EnCase/X-Ways são referências funcionais. Não prometer dados sobrescritos ou
admissibilidade judicial automática. Testar imagens com artefatos conhecidos.

**MobileScope:** backups/exportações Android/iOS legitimamente obtidos, diretórios,
SQLite, plist, configurações, imagens, metadados/apps, eventos, chamadas/mensagens
e localização apenas quando presentes e autorizados. Normalização, relações,
pesquisa/filtros, timeline/hash/evidência/relatório. Avaliar ALEAPP/iLEAPP;
Cellebrite/Magnet/Oxygen são referências, sem equivalência presumida ou bypass
de desbloqueio/criptografia. Validar resultados contra origem em dados próprios,
sintéticos ou autorizados. Não confundir perícia de backups com aquisição móvel.

DeepTrace correlaciona eventos, processos, arquivos, memória, conexões e logs,
mantendo hipóteses separadas de fatos. Aquisição de disco/memória/dispositivo
requer executor e procedimentos próprios; parser de arquivo não a comprova.

## G15 — NetworkTrace, MalwareLens e inteligência

NetworkTrace: PCAP/PCAPNG e captura autorizada, interface/origem/timestamp/filtros;
Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP/DNS/HTTP/TLS por metadados/DHCP conforme
suporte; conversações, origem/destino/portas, volume/duração/taxa/conexões,
reconstrução/artefatos quando viáveis e permitidos. Regras/anomalias, protocolos
inseguros, serviços/exposição, correlação, grafo/timeline/filtros e relatório.
Avaliar Wireshark/TShark, tcpdump, Zeek, Nmap e bibliotecas PCAP; NetworkMiner é
referência. TLS não pode ser presumido descriptografável. Testar tráfego conhecido.

MalwareLens: importação protegida, hash/strings/metadados, PE/ELF/importações/
bibliotecas/entropia/packing/assinaturas/indicadores/YARA, triagem e regras;
Ghidra, Volatility 3 e descompiladores/desmontadores legais, funções/referências/
anotações; dumps autorizados, processos/módulos/artefatos/timeline. Dinâmica
futura em sandbox descartável validada registra processos, arquivos, registro
Windows, conexões/persistência observável e artefatos. Avaliar sandbox aberta
mantida; IDA/Cuckoo são referências, não integrações presumidas. Começar por
binários benignos/testes sintéticos. Sem execução de malware no host, propagação,
persistência clandestina ou mecanismos de evasão ofensiva.

IntelScope/ExposureMap: domínios/subdomínios/DNS/certificados/registros públicos,
infraestrutura/tecnologias/serviços/metadados autorizados. ThreatPulse: indicadores,
enriquecimento, origem/data/versão, taxonomia/confiança, reputação, deduplicação,
histórico e relação com incidentes. Grafo domínio→IP→serviço→ativo→achado→risco,
filtros/comparações/exportação. Maltego/SpiderFoot/theHarvester/Shodan são
referências; não exigir serviço pago, contornar acesso ou coletar dados pessoais
sem finalidade legítima. APIs/fontes seguem termos/limites; dados públicos
podem estar errados. Testar proveniência, correspondência, erros e limites.

## G16 — Cloud, identidade, criptografia, IA e portfólio empresarial

| Área | Requisitos consolidados |
|---|---|
| CloudShield | AWS/Azure/GCP/VPS/híbrido/servidores, inventário autorizado, IAM, storage, rede/exposição, workloads, logs, permissões, segredos, criptografia, backups, containers/Kubernetes/IaC/CI/CD; APIs oficiais e menor privilégio, mudanças aprovadas |
| IdentityGuard | Inventário/contas privilegiadas e de serviço, IAM/RBAC/ABAC, MFA/SSO/OAuth/OIDC/SAML/PAM, AD/LDAP, sessões, permissões excessivas, eventos/mudanças e Zero Trust; leitura primeiro |
| CryptoGuard | Certificados/cadeias/validade/TLS, algoritmos obsoletos, parâmetros de hash, gestão/rotação/exposição de chaves, segredos e repouso/trânsito; recomendações de migração, bibliotecas maduras; resistência de senha somente autorizada, sem promessa de romper criptografia forte |
| AI Security | Código gerado por IA, dependências inexistentes/suspeitas, auth/validação/dados/admin, prompt injection direta/indireta, RAG, acesso a ferramentas, permissões, segredos, isolamento e integrações |
| Mobile Security | Apps Android/iOS, análise estática e dinâmica isolada, permissões/armazenamento/auth/criptografia/APIs/SDKs/dependências; MASVS/MASTG conforme compatibilidade; distinto de MobileScope |
| IoT | Inventário/firmware/atualizações, credenciais/configurações/serviços, criptografia e segmentação; preferir passivo e laboratório próprio |
| OT/ICS | Inventário, segmentação, acesso remoto, identidade, configuração, risco operacional/continuidade; IEC 62443/NIST 800-82; teste disruptivo real exige avaliação especializada |
| Privacy & Data Protection | Dados/classificação/fluxos, minimização, criptografia, retenção/exclusão/pseudonimização, incidentes de privacidade, apoio LGPD/ANPD |
| GRC | Riscos, políticas, evidências/auditorias, tratamentos/exceções, maturidade e recomendações; referências configuráveis, sem conformidade automática |
| Third-Party / Supply Chain | Fornecedores, dependências/SBOM/licenças/vulnerabilidades, APIs/integrações e riscos da cadeia |
| Continuidade / DR | BIA, serviços críticos, RTO/RPO, backups/restore, planos, exercícios controlados e relatórios |
| Human Security | Treinamento, phishing simulado autorizado, senhas/MFA, proteção da informação, questionários/trilhas e privacidade dos participantes |

## G17 — Intelligence Assistant e formação

Assistente técnico para triagem/logs/alertas, explicação de achados, hipóteses,
investigação/correlação/prioridade, código autorizado/patches/testes, regras,
comparações, relatórios e ensino. Modelos locais compatíveis com hardware e
provedores externos são opcionais. Sem API paga obrigatória.

Ferramentas tipadas, argumentos validados, contexto mínimo de autorização,
fontes/evidências, estados de incerteza e recomendações auditadas. Segredos fora
do contexto; não enviar a provedor sem autorização. IA não altera privilégios,
executa comandos arbitrários, ignora PolicyGate/aprovação, oculta falhas ou
transforma dados externos em instruções de autoridade.

Modo professor acompanha o desenvolvimento sem saltar fundamentos: computação;
Debian/terminal/Bash/permissões/systemd/APT/logs; redes/protocolos; Python,
TypeScript e Rust/programação segura; Git/banco/arquitetura; Blue/SOC/hunting;
Red Team/pentest autorizado; Purple/MITRE; AppSec/IA; forense/disco/memória;
malware/engenharia reversa; criptografia/cloud/identidade; Podman/KVM; defesa,
AutoDefense/recuperação; governança; testes e engenharia empresarial. Cada aula
tem teoria, propósito/riscos, exemplos, exercício seguro, comandos comentados,
resultado esperado e avaliação. Não presumir domínio apenas por entregar texto.

## G18 — Command Center, relatórios, métricas e serviços

Interface própria I.See: dark mode preto/grafite, contraste e acessibilidade,
navegação lateral, pesquisa/filtros, tabelas, dashboards/gráficos/grafos/timelines,
eventos e investigação/evidência. Responsiva, leve, contexto de organização,
estados de erro/vazio e ações reais. Exibir modo, permissão, ambiente, disponibilidade,
ferramenta externa, experimental/operacional e último teste. Animação só quando útil.

Áreas funcionais a integrar progressivamente: Overview; SOC/Detection; Assessments;
Universal Import Lab; AttackLab/ProofLab/ResilienceLab; Pentest/Red/Blue/Purple;
Endpoint/NetworkTrace; BarrierMatrix/AutoDefense/Self-Healing/ResponseGrid;
SecureBuild/Code Audit/Remediation; Vulnerability/Exposure/Hunting/Intelligence;
Malware/Forensics/MobileScope; Identity/Cloud/Mobile/IoT/OT/AI/Crypto;
Privacy/GRC/Continuity/Human/Third-Party; RiskGraph/EvidenceChain/PolicyGate;
Authorization/Execution; Services/Clients; Reporting/Assistant/Integrations;
System Health/Audit/Settings. Nomes de navegação não exigem páginas vazias.
AttackLab inclui operações, inventário/superfície, adaptadores, execuções aprovadas,
resultados/evidências, Blue/Purple, correções, antes/depois e relatórios.

Relatórios técnicos/executivos para auditoria, pentest/vulnerabilidades, código/
API/software, rede/cloud/identidade, incidentes/perícia/malware, Purple, governança,
disponibilidade/correção/comparação. Conteúdo: projeto, objetivo, escopo/autorização,
metodologia/datas/ferramentas, testes/limites, achados/evidências, impacto/severidade/
confiança, recomendações/prioridade/status, correções/retestes/risco residual,
conclusão técnica e resumo executivo. PDF e formatos estruturados quando
implementados; nenhuma prova inventada. Exportação deve preservar contexto e acesso.

Métricas com fonte/período/denominador: ativos/telemetria, achados/correções
verificadas, tempo de triagem/detecção/resposta/recuperação, falsos positivos,
barreiras, backups/restores, testes e exercícios Purple/controles demonstrados.

Services Management organiza problemas do cliente: auditoria, pentest/Red/Blue/
Purple, AppSec/correção/hardening, SOC/monitoramento/hunting, resposta/perícia/
recuperação, cloud/identidade/mobile/IoT/OT/IA, GRC/LGPD, continuidade, treinamento,
consultoria/vCISO. Serviços recorrentes, equipes, MSSP/MDR e distribuição comercial
dependem de capacidade e liberação comprovadas; não antecipar cobrança/SaaS.

## G19 — Execution Center, contratos de dados e CLI

Orquestrador central persistente inicialmente em PostgreSQL, para importação,
análise/teste/relatório/laboratório: ID, projeto/operador/módulo/operação,
parâmetros validados, prioridade, estado, criação/início/fim, timeout/recursos,
resultado/evidências/histórico de erros. Estados: **Pending, Validating, Awaiting
Approval, Queued, Running, Pausing, Completed, Failed, Cancelled, Timed Out**.
Controlar concorrência, idempotência, cancelamento e recuperação após reinício;
não duplicar ação não idempotente. Tabela de jobs sozinha não é orquestrador.

Modelos versionados: Organization/User/Role/Permission, identidades de serviço,
Project/Asset/Service/Technology/Application/Endpoint/NetworkInterface,
Authorization/Scope/Engagement, Assessment/Plan/Run, TestDefinition/Execution,
Event/Rule/Alert/Incident/Case/Finding/Vulnerability, Evidence/Transfer/Transformation,
Indicator/Risk/Relationship/Control/Barrier/Evaluation, ResponseAction,
RemediationPlan/Change/PatchCandidate/Deployment/Recovery/Verification,
Retest/Comparison/Report, Agent/Integration/Tool/LabEnvironment/Exercise/Simulation,
Job/AuditEvent. Criar entidades ao implementar fluxo útil, com IDs, FKs/índices,
restrições, organização/projeto e retenção; evitar duplicar dados sensíveis.
Migração já entregue/aplicada não é reescrita para acomodar nova funcionalidade.

Interfaces CLI propostas, ainda sujeitas a implementação/teste individual:

```text
sentinel lab list | lab start --scenario ID | lab stop --scenario ID
sentinel demo run --scenario ID
sentinel import url --project ID --url URL
sentinel import file --project ID --path CAMINHO
sentinel import git --project ID --repository REPOSITORIO
sentinel scope validate --project ID
sentinel assessment plan --project ID
sentinel assessment run --plan ID
sentinel assessment status --run ID
sentinel assessment report --run ID
sentinel remediation propose --finding ID
sentinel remediation validate --change ID
sentinel compare create --baseline VERSAO_A --candidate VERSAO_B
sentinel compare report --comparison ID
```

CLI/painel usam a mesma autorização; nenhum comando contorna PolicyGate.

## G20 — Integrações, licenças e referências

Integration Framework declara nome/versão/origem/licença, compatibilidade/SO,
permissões, offline/rede/custo, entradas/saídas/contratos, riscos, limites e testes.
Tipos: Native Engine, Open-Source Adapter, External Service Adapter, Operating
System Adapter, Laboratory Adapter e Commercial Tool Connector autorizado.
Exibir dependência de terceiros; verificar documentação/versão/manutenção/licença/
redistribuição/acesso antes de implementar. Não copiar código fechado, remover
atribuição, contornar licença ou presumir API comercial pública.

Além das integrações por área, avaliar OpenSSL, MITRE Caldera e DFIR-IRIS quando
justificadas; não instalá-las apenas por constarem do catálogo. A matriz de
capacidades registra ferramenta de referência, problema, funções/motor, próprio
ou integrado, dependências/SO/rede/licença/autorização, limites/testes/evidências,
estado/prioridade. Confrontar qualquer catálogo completo futuro item a item.

Referências aplicáveis/versionadas: OWASP Top 10/WSTG/ASVS/API Top 10/MASVS/MASTG/
SAMM/GenAI/Cheat Sheets, MITRE ATT&CK/D3FEND, NIST CSF/SSDF/800-207/800-61/800-82,
CIS Controls, ISO 27001/27002/27005, IEC 62443, LGPD/ANPD, PCI DSS quando cabível,
CWE/CVE/CVSS/EPSS/CISA KEV, Sigma/YARA, STIX/TAXII, SARIF e CycloneDX. Verificar
versão vigente ao utilizar; a enumeração não comprova conformidade/certificação.

## G21 — Engenharia e segurança obrigatórias (§53 unificado)

Além dos contratos, dados, jobs, catálogo/adaptadores e isolamento definidos acima:

- Segurança interna: MFA/sessões/RBAC, CSRF, limites de login, backend por recurso,
  SQL parametrizado, anti-command injection/SSRF/traversal/uploads, validação de
  webhooks, controle de plugins, runtime mínimo e identidades separadas. Localhost
  por padrão; acesso administrativo remoto somente explicitamente configurado.
- Segredos: centralização, criptografia, temporariedade, rotação, acesso/auditoria,
  retenção, backup protegido, recuperação/exclusão apropriada; sem plaintext em
  logs, relatórios, Git, argumentos de processos ou histórico do terminal.
- Adaptador: checar dependência/versão/escopo, validar entrada, parametrizar,
  impor limites, isolar, coletar/normalizar, tratar erro, preservar evidência e
  liberar recursos. Sem privilégios administrativos por padrão.
- Catálogo de teste: ID/nome/categoria, vulnerabilidade/referência, implementação/
  versão, requisitos/SO/ambiente/impacto/autorização, entradas/parâmetros/limites,
  ações CLI/painel, timeout/cancelamento/evidência, sucesso, limitações/falsos
  positivos/recomendação/regressão/estado. Definição não comprova executor.
- Observabilidade: logs estruturados, métricas/health, jobs/erros/consumo,
  integrações/VMs/agentes e alertas operacionais; retenção/redação/acesso.
  Diferenciar falha do Sentinel de vulnerabilidade no alvo.
- Falhas: worker/backend/rede/VM/banco/disco, timeout/cancelamento/parcial/reinício;
  não perder histórico silenciosamente, preservar resultados parciais e limpar
  recursos com recuperação consistente.
- Distribuição: scripts, serviços necessários, dependências, instalação,
  compatibilidade de versões, atualizações verificadas, migrações/diagnóstico,
  backup/restore/rollback e desinstalação limpa. Requisitos mínimos/recomendados
  medidos, sem GPU obrigatória. Agentes removíveis pelo administrador legítimo.

Documentar arquitetura/fluxos/fronteiras, contratos de API/dados/eventos/testes,
políticas/matriz de permissões, ameaças, risco, recuperação/procedimentos, decisões
e validação. Reutilizar documentos existentes em vez de duplicar contraditoriamente.

## G22 — Validação, maturidade e definição de pronto

Cada módulo entrega objetivo/casos de uso, requisitos funcionais/não funcionais,
arquitetura/interfaces/dados/dependências, ameaças/controles, código integrado,
testes/evidências/métricas, documentação, limites/compatibilidade e maturidade.
Testes relevantes incluem unitários, integração, E2E, segurança/permissões,
regressão, parsing/integridade, falsos positivos/negativos, desempenho/recursos,
isolamento, cancelamento/recuperação, compatibilidade, instalação/migração/rollback.
Registrar objetivo/pré-condições/entrada/esperado/observado/evidência/data/revisão/
ambiente/status. Não marcar teste não executado como aprovado.

Aceite inclui fluxos reais: auditoria→achado→relatório; barreira→teste→evidência;
evento→detecção→alerta→incidente; patch→aprovação→aplicação→reteste; falha→restore
→integridade; Purple→telemetria→melhoria; artefato/imagem→hash→timeline→relatório;
PCAP→protocolo/fluxo→regra→correlação; e bloqueio comprovado de acesso fora do
escopo. Fixture é identificada como tal; laboratório não libera cliente.

Estados V6.9: não iniciado, especificado, em desenvolvimento, parcialmente
implementado, em validação, validado em laboratório, validado internamente,
validado para clientes, disponível comercialmente. Preservar M0–M6 histórico
(planejado/protótipo/integrado/testado/operacional interno/preparado comercial/
Enterprise validado), sem conversão automática. Matriz, código e evidência devem
concordar. Ferramenta instalada não significa integração operacional.

Pronto no recorte exige código, interfaces, testes relevantes aprovados,
permissões verificadas, falhas definidas, limites documentados, evidência e
maturidade correta. Liberação profissional exige adicionalmente isolamento,
erros/cancelamento, recursos, evidências/relatórios, recuperação e aprovação de
liberação. Classificar como planejado/experimental/validado em laboratório/
validado internamente/liberado para atendimento; avaliação independente sustenta
a maturidade Enterprise. Nenhuma lista de testes substitui sua execução.

## G23 — Git privado, memória portátil e migração

Repositório privado autorizado: `securityMaker488/isee-sentinel`. Manter histórico,
branches, `.gitignore`, `.gitattributes`, lockfiles e commits claros. Antes de
commit/push, verificar arquivos rastreados e histórico com o guarda do repositório
e revisão dos arquivos. Não incluir `.env` real, bancos/credenciais/certificados
privados, chaves ou evidências sensíveis. Não apagar histórico, trocar remoto,
usar force-push ou tornar público sem autorização específica.

Memória versionada: `AGENTS.md`, `PROJECT_STATE.md`, `ROADMAP.md`, este guia,
matriz/catálogo de capacidades, `ARCHITECTURE.md`, `DEVELOPMENT.md`,
`MIGRATION-DEBIAN.md`, `README.md`, segurança/ameaças, autorização/laboratório,
testes/validação, importação/remediação/CLI, integrações/licenças, incidente/
backup/recuperação e decisões. Aliases históricos apontam ao documento vigente;
não depender da conversa ou de caminhos pessoais na nova máquina.

Scripts setup Windows/Debian, doctor, exemplo de configuração e lockfiles devem
verificar requisitos, orientar ausências, preparar/validar e explicar erros, sem
operações de disco/boot. Separar dev/produção, usar caminhos portáveis e tratar
SO, permissões e formatos. CI Windows/Ubuntu testa compatibilidade; Ubuntu não
é homologação Debian. Testes não executados ficam explícitos.

Após terminar o possível no Windows: instalar Debian separadamente por ação
autorizada, preservar Windows/dados/recuperação, validar ambiente, instalar Git/
runtimes de fontes oficiais, autenticar conta, clonar privado, configurar o método
oficial compatível de Codex/VS Code, rodar setup/doctor/testes e retomar checkpoint.
No fluxo inverso, conferir mudanças locais e sincronizar antes de alternar máquina;
resolver conflitos preservando trabalho, nunca sobrescrever alterações não
sincronizadas. Backup/bundle sem segredos é alternativa de transporte, não cópia
do banco operacional. Instalação de SO é distinta do desenvolvimento autorizado.

## G24 — Linha única de fases e critérios

| Fase global V6.9 | Entrega e gate |
|---|---|
| 0 Auditoria | Inventário/arquitetura/riscos e cobertura confrontados com código; retomar registros, auditar mudanças dirigidas |
| 1 Fundação | Identidade/clientes/PostgreSQL, autorização/PolicyGate/evidência, plano de avaliação e contratos; isolamento e falhas testados |
| 2 Universal Import Lab | Preservação/quarentena/identificação, formatos seguros individualmente, Git/URL controlados e plano de avaliação |
| 3 ProofLab | Importar aplicação de laboratório → isolar → avaliar → demonstrar/evidência → corrigir cópia → retestar/comparar → relatar |
| 4 Security Assessment | Catálogo e Web/API/SAST/SCA/DAST/infraestrutura progressivos, adaptadores licenciados e evidências |
| 5 Remediation | Branch/diff/revisão/teste/homologação, aprovação, aplicação/rollback e reteste comparável |
| 6 Execution Center | Fila PostgreSQL/CLI, prioridade/estados/cancelamento/retomada, idempotência e recursos; antecipar só dependências mínimas necessárias |
| 7 SOC e defesa | Telemetria, regras/hunting/casos, barreiras/ResponseGrid/contenção/recuperação e perícia de resposta |
| 8 Laboratórios avançados | QEMU/Kali/VMs/redes/snapshots, Purple, ResilienceLab e dinâmica após isolamento validado |
| 9 Segurança empresarial | Cloud/identidade/IA/mobile/IoT/OT, perícia especializada, inteligência e exposição/risco |
| 10 Governança | GRC/privacidade/terceiros, continuidade/BIA/RTO/RPO e formação de clientes |
| 11 Serviços gerenciados | Operação recorrente/equipes/serviços por cliente com responsabilidades, acesso e continuidade |
| 12 Enterprise | Distribuição/manutenção/hardening/performance/licença/suporte, recuperação/validação independente e liberação profissional |

Preservar fatias já entregues de fases posteriores. Não confundir reaproveitamento
com fechamento da fase. O primeiro ciclo integrado segue fundação → importação →
autorização aplicada → ProofLab → assessment → correção → reteste/relatório.

| Fase interna AttackLab | Lugar na linha global e ordem própria |
|---|---|
| A1 Auditoria | Global 0; auditoria dirigida e plano já registrados, sem reiniciar revisão ampla |
| A2 Núcleo seguro | Global 1, com dependências mínimas da 6; operação/manifesto/escopo/limites/auditoria antes de novos executores |
| A3 Adaptadores | Global 2/4; inventário, Nmap controlado e Gobuster offline primeiro, respeitando o núcleo seguro |
| A4 Evidence Fusion | Transversal 1/4/5/7; persistência/normalização/relações/timeline/grafo/comparação após os contratos |
| A5 Blue/Purple | Global 7/8; Suricata/Sigma, metadados Atomic/MITRE e resultados manuais antes de automação de cenários |
| A6 Segurança/validação | Gates de cada fase e global 12; escopo, cancelamento, integridade, offline, desempenho e isolamento comprovados |

## G25 — Estado conhecido e ponto de retomada da consolidação

Esta seção registra o checkpoint **anterior ao novo incremento**, em `749bf63`;
o estado mais recente sempre fica em `PROJECT_STATE.md`. Não é nova auditoria do
código nem nova execução das suítes.

| Recorte comprovado no checkpoint | Limite que permanece |
|---|---|
| Fundação React/Fastify/PostgreSQL, operador/MFA/recuperação, organizações/projetos/ativos, escopos e evidências/auditoria | Homologação Debian, retenção e contratos gerais ainda incompletos |
| Authorization Manager/API/UI, migração 009, comprovação cifrada, responsável, hash/revisão/aprovação, perfis/bytes/portas, substituição/revogação | Alvo exato/exclusões ainda não fazem parte do hash aprovado; operação/plano completo, taxa/CPU/RAM e interrupção emergencial pendentes |
| Agente Rust autenticado com HMAC/FIM, baseline aprovada, alertas/replay/idempotência/revogação | Não é EDR completo nem serviço Linux homologado; ampliar processos/serviços/logs/conexões |
| Casos/notas/evidências/relatórios, SecureFix de cópia SSH e RiskGraph integrado | Correção/rollback do host, operação→teste→observação→reteste e comparação ampliada pendentes |
| ZIP cifrado, até 16 MiB, 512 entradas/64 MiB expandidos, validações sem extrair/executar/rede | TAR/TAR.GZ, URL/Git e demais formatos; ZIP64/descriptors/aninhados não suportados |
| Análises offline de dependências/CycloneDX/NmapXML/HAR/SARIF/IAM/S3/identidade/IA/PE/ELF/scripts/timelines/OpenAPI e perícia PCAP/PCAPNG/SQLite/plist | Escopo delimitado; não significa pentest, aquisição forense, decompilação ou dinâmica completos |
| Nmap com argumentos estruturados e limites em testes injetados | Binário real não homologado; demais adaptadores AttackLab/Blue/Purple não implementados |
| Auditoria/plano do complemento AttackLab e GitHub privado sincronizado | Auditoria A1 não conclui A2–A6; CI Ubuntu não substitui Debian/Kali |

Evidência anterior: 146 testes JS/TypeScript; 20 casos Authorization Manager em
PostgreSQL nativo/runtime restrito; backup/restore de 36 tabelas e 9 migrações;
QA do fluxo de autorizações no navegador. Rust/Python e outras suítes históricas
constam de `VALIDATION_REPORT.md`, com revisões e skips próprios. Não somar
execuções históricas como teste novo. Resultado remoto da correção CI fica no
checkpoint/relatório atualizado, não inferido neste guia.

**Retomada definida ao consolidar:** global fase 1 / AttackLab A2. Ligar manifesto
imutável de alvos/exclusões ao mandato existente e ao hash revisto, começando
pelo IPv4 literal/portas já suportados. Validar cadastro/despacho, negação de
exclusões e alteração de endereço, revogação/expiração, projeto/organização,
parâmetros e integridade. Usar migração nova 010 ou posterior, nunca editar as
001–009 aplicadas. A aprovação existente não autoriza IP acrescentado depois.

Após concluir esse gate, a fila única preserva plano de avaliação, TAR/TAR.GZ e
URL/Git, ProofLab, assessment/correção e jobs; a evolução interna AttackLab segue
inventário/Gobuster offline, Evidence Fusion e Blue/Purple nas dependências
correspondentes. Não abrir uma segunda linha de desenvolvimento que abandone
as fases globais. Linux SUID/SGID/Auditd/Suricata real e QEMU/KVM/Kali exigem a
etapa Debian, enquanto contratos/parsers/API/UI podem avançar no Windows.

## G26 — Conflitos resolvidos e manutenção do guia

| Texto histórico | Diretriz consolidada |
|---|---|
| Arch principal / Ubuntu Server recomendado (V5) | Debian 13 KDE principal futuro, Windows atual preservado; Ubuntu é compatibilidade/CI, não migração concluída |
| Começar só depois da migração (V6.3 e fases antigas) | Preferência posterior: completar trabalho Windows possível, homologar capacidades Linux no Debian |
| Fases V6.5 0–10 / V6.6 0–16 | Uma sequência global V6.9 0–12; a antiga migração tornou-se dependência transversal |
| SaaS/produto comercial no horizonte | Private Operator primeiro; arquitetura extensível sem complexidade pública/comercial prematura |
| Repetir auditoria integral antes de toda modificação | Auditoria inicial preservada; checkpoint e inspeção dirigida em continuação, conforme instrução posterior do operador |
| Autonomia crítica emergencial genérica da V5 | Ação crítica/produção exige aprovação específica e controles; automação não amplia a própria autoridade |
| Exemplos de ferramenta/comando/camada | Requisito/proposta, não prova de implementação, autorização, proteção ativa ou licença |
| M0–M6 / novos estados de maturidade | Preservar histórico e declarar estado funcional com evidência, sem promoção automática |
| “Não publicar repositório” no suplemento | Manter privado; criação e push privados posteriormente autorizados não permitem torná-lo público |

Para novo prompt: identificar adições e conflitos, atualizar este guia e o mapa
de cobertura, preservar fonte/hashes, inserir dependências na fila existente e
registrar o ponto de retomada. Se houver divergência de status, consultar o último
checkpoint, commit e evidência, corrigindo o documento desatualizado. Não ler
todos os originais novamente sem uma razão concreta.
