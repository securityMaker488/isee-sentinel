# Registro de verificação — Private Operator Edition / especificação V6.5

Consolidação: **24/10/2026**, fuso America/Bahia. Os resultados abaixo foram observados nas execuções desta sessão de engenharia. Não representam uma avaliação independente, certificação, liberação comercial ou homologação do Debian.

## Ambiente e separação dos testes

- Host acessível: Windows 10 Pro 10.0.19045; Node.js 24.21.0; Python 3.11.9. O diagnóstico completo está em `DIAGNOSTICO.md`.
- Testes padrão da API: PostgreSQL embarcado PGlite em banco isolado de teste, sem dados de clientes.
- Testes nativos: PostgreSQL **18.6**, em instância temporária própria, ligada somente a `127.0.0.1:55432`. O serviço PostgreSQL preexistente do computador não foi reutilizado.
- A fixture nativa usa uma identidade de preparação do banco e outra identidade **`sentinel_runtime`** na API, com os privilégios de `ops/runtime-grants.sql`.
- Os usuários adicionais e empresas das fixtures existem para testar negativas e isolamento. Apenas o fundador vinculado em `private_operator` pode autenticar na edição privada; eles não representam contas públicas ou operadores habilitados no produto.
- O banco de QA do navegador é temporário. As configurações e os eventos de laboratório estão identificados como sintéticos; os achados e alertas são resultados efetivamente calculados e persistidos a partir dessas entradas.

## Execuções confirmadas

| Verificação | Resultado observado | Escopo e limite |
|---|---|---|
| `npm run check` | Build e verificação TypeScript aprovados; **37 testes aprovados** | 17 do pacote core, 19 de integração API e 1 de configuração; não é cobertura de toda a especificação |
| Integração API em PostgreSQL 18.6 nativo | **19 testes aprovados**, com `sentinel_runtime` na API | Mesmos fluxos funcionais e de segurança no banco nativo; fixture preparada por identidade separada |
| Agente Rust | **9 testes aprovados** | Protótipo offline, consentimento, arquivo explícito, hash e limites; não é um sensor EDR residente |
| Validador Python | **8 aprovados; 1 ignorado por depender de Unix** | Inclui fluxo real Rust → Python; não valida Linux por execução no Windows |
| Backup PostgreSQL e restauração | `pg_dump` e `pg_restore` concluídos; **14 tabelas comparadas sem diferenças** | Restauração em banco novo e separado; cadeia de auditoria íntegra |
| Navegador: login MFA, ativo, autorização e análise | Ações e resultados verificados | O scanner produziu dois achados SSH a partir de arquivo de laboratório |
| Navegador: relatório, SOC e evidência | Download JSON, alerta persistido de cinco eventos sintéticos e detalhe de integridade verificados | Não equivale a monitoramento de host, sensor autenticado ou investigação de invasão real |
| Navegador: viewport móvel | Ausência de overflow horizontal verificada em 390 × 844 | Não substitui auditoria completa de acessibilidade ou matriz de dispositivos |
| Navegador: empresas, contexto e projetos | Criação de empresa, troca de contexto, projeto novo e isolamento de dados verificados | Dados da empresa anterior não permaneceram no contexto novo |
| `npm audit`, 24/10/2026 | **Zero vulnerabilidades conhecidas** no relatório de 275 dependências | Inventário gerado possui 272 entradas; contagens têm escopos diferentes. Ausência de avisos não comprova ausência de vulnerabilidades |

O teste final do navegador concluiu **12 passos aprovados**, incluindo login MFA, ativos, escopo, scanner, relatório, SOC, evidências, criação de empresa, troca de contexto, novo projeto, isolamento de dados e viewport móvel. O favicon foi corrigido; a execução final não registrou erros JavaScript ou de console. As capturas `outputs/sentinel-command-center.png`, `outputs/sentinel-soc.png` e `outputs/sentinel-mobile.png` foram atualizadas e inspecionadas. No viewport de 390 px, a barra lateral fechou após a transição sem overflow horizontal. Esses resultados aprovam o fluxo exercitado, não uma matriz abrangente de navegadores, acessibilidade ou carga.

Rustfmt e Clippy não estavam instalados no toolchain disponível; os comandos não foram aprovados nem os componentes instalados globalmente. A sintaxe de `scripts/diagnose-linux.sh` foi verificada com `bash -n` no Git Bash; o script não foi executado em Debian.

## Casos de segurança exercitados

| Requisito verificável | Evidência executada |
|---|---|
| Identidade privada | Negação sem sessão, senha/MFA, replay de TOTP, rejeição de usuário fora do fundador, unicidade do fundador |
| Sessões e abuso | Cookie HttpOnly/SameSite, CSRF/origem, expiração, logout, limite persistido por conta e recuperação com revogação de sessões |
| Recuperação administrativa | Código inválido rejeitado; código correto consumido; senha e TOTP rotacionados; reutilização rejeitada |
| Autorização | Escopo obrigatório inclusive para administrador; organização, ativo, ambiente, operação, papel, início, expiração e revogação |
| Contexto de empresa | Troca autorizada com rotação de CSRF; bloqueio de organização sem vínculo; projetos e recursos fora do contexto inacessíveis |
| Entradas e arquivos | Campos extras rejeitados; caminhos absolutos/traversal/esquemas ambíguos e tamanhos excessivos bloqueados; conteúdo não executado |
| SecureBuild | Regras de configuração, comentários e contextos ambíguos, localização JSON e supressão de conteúdo sensível nos achados |
| Evidência | Bytes e SHA-256 preservados; cifra autenticada; adulteração/contexto criptográfico incorreto detectados; mutação ordinária bloqueada |
| Auditoria | Cadeia de hashes verificada; acesso/exportação rastreados; proteção contra alteração ordinária |
| Detecção | Cinco falhas por janela, deduplicação de evento, conflito de idempotência, alerta/incident vinculado e triagem |
| Isolamento de simulação | Evento sintético recusado para ativo de produção; organização e campos de correlação segregados |
| Regressão de correlação | Delimitadores em `source` e `subject` não causam supressão indevida entre contextos distintos |
| Perfil V6.5 de banco | PostgreSQL exige configuração explícita; ausência da URL não ativa PGlite silenciosamente |

Esses casos apoiam os temas de autenticação, sessões, autorização, validação de entrada e integridade citados na arquitetura OWASP/NIST. Não há declaração de atendimento integral a uma norma, nem atribuição de controles específicos não avaliados.

## Restauração verificada

A execução nativa final comparou dados antes e depois da restauração, inclusive campos cifrados e metadados:

| Tabela | Registros comparados |
|---|---:|
| `organizations` | 4 |
| `users` | 5 — fixture de negativas, com fundador único controlado |
| `projects` | 1 |
| `assets` | 4 |
| `authorizations` | 3 |
| `scans` | 1 |
| `findings` | 2 |
| `evidence` | 2 |
| `security_events` | 22 |
| `audit_events` | 62 |
| `incidents` | 4 |
| `alerts` | 4 |
| `private_operator` | Conteúdo integral idêntico |
| `operator_organizations` | Conteúdo integral idêntico |

A cadeia de auditoria foi verificada em cada organização restaurada. Este exercício demonstra recuperação do banco da fixture e preservação dos campos cifrados. Não mede RPO/RTO, não testa recuperação de chave perdida, não homologa backup do HD externo e não confirma, por si só, o procedimento operacional completo no Debian. A descriptografia e exportação dos originais foram exercitadas nos testes da API, não como uma nova homologação de chave após esta restauração.

## Estado das fases 0–10

| Fase | Estado sustentado pelas evidências | Próximo requisito não concluído |
|---|---|---|
| 0 — Debian | Diagnóstico e roteiro seguro preparados; instalação não executada | Identificar partições, testar backup, preparar mídia e validar plano de migração antes de alterações |
| 1 — Estação | Ferramentas usadas no Windows | Instalar e homologar runtimes, drivers e ferramentas no Debian 13 KDE |
| 2 — Núcleo | Fatia integrada e testada, **M3 no recorte** | Homologação operacional, acessibilidade abrangente, retenção, atualização e operação assistida antes de M4 |
| 3 — Primeira detecção | Regra, ingestão, alerta, persistência e UI testados; Rust/Python offline testados como protótipo | Agente Linux integrado e autenticado, coleta nativa e testes Debian |
| 4 — SecureBuild | Baseline estático, detecção limitada de segredos, evidências e relatório testados | Análise abrangente de dependências, autenticação/autorização, APIs e linguagens |
| 5 — Ambientes opcionais | Planejamento de Podman rootless e Kali/KVM | Instalação autorizada, isolamento e recuperação efetivamente testados |
| 6 — Defesa | Catálogo/avaliações estáticas e detecção inicial; cálculo de risco do core integrado ao relatório JSON e testado | Grafo de risco na UI, contenção, patches, aprovação/aplicação, rollback e recuperação controlados |
| 7 — Laboratórios e investigação | Evidência e hash de arquivos pequenos testados | Forense especializada, AttackLab/PurpleMatrix e análise dinâmica isolada |
| 8 — Adaptadores externos | **M0** | Base validada e demanda autorizada; sem Firebase/Supabase internos ou adaptadores operacionais |
| 9 — Windows | Núcleo e protótipo offline testados neste host | ETW/Event Log, serviço de agente, instaladores e atualização segura |
| 10 — Enterprise | **M0** | Validação independente e requisitos comerciais/operacionais comprovados |

Nenhum resultado acima promove a plataforma completa a M4, M5 ou M6. O inventário detalhado está em `MODULOS-E-ACEITACAO.md`; os gates e a preparação segura do Debian estão em `FASES-V6.5.md`.

## Reprodução e próximos registros

Use as suítes do repositório em bancos exclusivos de teste. `npm run check` usa o perfil isolado padrão. Para repetir a integração nativa, prepare um banco vazio separado, uma identidade de fixture e a identidade `sentinel_runtime`, e forneça `SENTINEL_TEST_DATABASE_URL` e `SENTINEL_TEST_RUNTIME_URL` por ambiente privado antes de executar `tsx --test apps/api/test/integration.test.ts`. A fixture aplica `ops/runtime-grants.sql`; não a aponte a bancos com dados reais. Não publique URLs contendo credenciais.

Os testes de Rust/Python e seus comandos de reprodução estão nos READMEs dos respectivos diretórios. O fluxo de backup operacional está em `OPERACAO.md`.

Ainda faltam testes de falha de processo/banco, disco cheio, concorrência sustentada, retomada de jobs, rotação/perda de chave, atualização segura, fuzzing, quotas/retenção, acessibilidade abrangente e isolamento efetivo de VMs/contêineres. Não existem resultados inventados para essas capacidades.
