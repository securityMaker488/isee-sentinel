# Validação de desenvolvimento — Windows — 26/10/2026

Especificação V6.9, versão de desenvolvimento 0.2.0. Resultados de fixtures
sintéticas e ambientes locais controlados. Não constituem homologação Debian,
liberação para clientes, certificação ou prontidão comercial.

## Incremento Authorization Manager

| Verificação executada em 26/10/2026 | Resultado |
|---|---|
| TypeScript/API e build React/Vite | Passaram |
| Suíte JS completa com Python real configurado | 146 passaram, sem falhas nem skips |
| Política estruturada | 13 testes novos incluídos na suíte completa |
| Authorization Manager na API | 20 testes novos incluídos na suíte completa |
| Os mesmos 20 testes em PostgreSQL18, runtime restrito | Passaram; migração009 e novos grants exercitados |
| Backup/restore nativo | 36 tabelas idênticas, 9 migrações, auditoria íntegra; 30 mandatos e31 vínculos |
| Navegador Edge/Playwright, fluxo de autorização | Rascunho, download da prova, revisão, aprovação, limites, bloqueio legado, revogação e viewport390px passaram; console sem erros |

Foram exercitados alteração de risco/perfil por novo rascunho, imutabilidade,
projetos/empresas isolados, falha de integridade, vigência, bytes UTF-8 reais,
portas permitidas, observação assinada do agente e transições de cópia SecureFix.
Os testes de autorização usam substitutos de Nmap/workers para provar que a
política bloqueia antes do despacho. A suíte completa também executou os testes
existentes com Python real. Rust e suítes Python isoladas não foram repetidos:
suas fontes não mudaram neste incremento. Credenciais de QA não foram versionadas.

Script reproduzível: `scripts/browser-authorization-qa.cjs`. Capturas em
`.sentinel/qa/authorization-approved.png` e `authorization-mobile.png`.
Uma tentativa de navegador precedeu o término da inicialização do servidor e
recebeu conexão recusada; após a prontidão, o fluxo completo acima passou.

## Checkpoint anterior preservado

Os resultados abaixo são históricos do incremento anterior, não uma segunda
execução das suítes inalteradas neste incremento.

| Verificação executada | Resultado e alcance |
|---|---|
| `scripts/setup-windows.ps1` | Passou: diagnóstico, instalação pelo lockfile sem scripts, build React/TypeScript e Rust |
| `npm test` com `SENTINEL_TEST_PYTHON_PATH` | 113 passaram, sem falhas ou skips; inclui Python real de perícia e ZIP |
| Rust `cargo test --locked` | 18 passaram: 14 biblioteca/transporte + 4 CLI |
| Python integridade | 8 passaram; 1 específico de Unix ignorado no Windows |
| Python perícia | 16 passaram: PCAP/PCAPNG/SQLite/plist e entradas malformadas |
| Python ZIP | 12 passaram: caminhos, links, colisões, tamanho, CRC, metadados, consentimento e ausência de extração |
| Guarda do repositório | 3 passaram, incluindo segredo no índice já removido da cópia de trabalho |
| API ZIP no PostgreSQL nativo | 6 passaram com runtime restrito; Python real positivo e negativo |
| API perícia no PostgreSQL nativo | 5 passaram com runtime restrito, incluindo Python real |
| API agentes/análises no PostgreSQL nativo | 6 passaram no checkpoint anterior; não representa Linux |
| Binário Rust real → API | Passou coleta autorizada, HMAC, baseline, alteração, alerta e revogação |
| Backup/restore PostgreSQL 18 | 34 tabelas comparadas linha a linha; 8 migrações; auditoria íntegra |
| Navegador Edge/Playwright | Fluxo completo passou, incluindo viewport de390px e console sem erros |
| Auditoria npm | Nenhuma vulnerabilidade reportada pela base consultada; não prova ausência de falhas |

Nas suítes JS, Rust, Python e guarda: **170 testes passaram e 1 foi ignorado**.
Integrações nativas e navegador são verificações adicionais, sem duplicar essa
soma. Resultados correspondem à execução registrada, não a futuras alterações.

## Percurso no navegador

Login/MFA; ativo e escopos; SecureBuild e relatório; SOC sintético; evidência;
cadastro/download único e revogação do agente; nota/evidência/transição/relatório
do caso; proposta SSH, aprovação, aplicação à cópia, verificação e restauração;
análise de dependências; ZIP com Python real e quarentena; PCAP com Python real;
RiskGraph acessível; Nmap indisponível com execução desabilitada; matriz;
isolamento entre empresas/projetos; layout estreito e console sem erros.

Falhas encontradas e corrigidas: rótulos acessíveis de selects/textarea e limite
global insuficiente para atualizações do painel. O teto geral passou de200 para
600 requisições/minuto; login mantém10/minuto e bloqueio persistente por conta.
MFA, CSRF e autorização continuam cobertos pelos testes. O replay completo do
navegador passou após as correções.

## Limitações

O restore anterior usou banco sintético com dados de importação; o atual usou
os registros dos testes de autorização, agente e cópia SecureFix. Tabelas sem registros
foram comparadas vazias. Validou conteúdo cifrado idêntico e cadeia de auditoria,
sem exercitar todos os tipos populados, perda elétrica ou custódia de chave de
instalação real. Banco temporário em55432, separado do serviço preexistente5432.

Nmap foi testado com executor injetado. Nmap real, Kali/QEMU, redes isoladas,
desempenho sustentado, fuzzing ampliado, CI remota e Debian permanecem pendentes.
Python `-I`, ambiente reduzido e timeout não constituem VM nem bloqueio de rede
imposto pelo SO. Os workers implementados não acessam rede nem executam entradas.

Fastify emitiu aviso de depreciação de `disableRequestLogging`, sem falha. Avaliar
migração dessa opção junto a atualização compatível, preservando a redação de logs.

Reprodução: TESTING.md, DEVELOPMENT.md e scripts versionados. Credenciais de QA,
bancos, chaves e dumps não integram o Git ou pacote. Screenshots de dados
sintéticos ficam em `.sentinel/qa` e cópias selecionadas na pasta de entrega.
