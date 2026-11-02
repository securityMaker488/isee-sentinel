# Estado do projeto — 01/11/2026

## Retomada — uma linha de desenvolvimento

Requisitos: docs/GUIA-MESTRE-CONSOLIDADO.md. Fila: ROADMAP.md.
Fontes/hashes: docs/PROMPT-COVERAGE.json. Ao receber “continue”, usar este
checkpoint e somente os arquivos da tarefa. Não repetir auditoria ampla nem
reler todos os prompts. Ordem global V6.9 fases0–12; AttackLab A1–A6 internas.

**Posição: fase global1 / AttackLab A2, parcialmente entregue.** Plano versionado
com execução estática integrada concluído neste recorte. Windows e plataforma
inteira ainda NÃO estão100% concluídos. Completar desenvolvimento portátil no
Windows; quando restarem somente tarefas dependentes de Linux, parar e continuar
pelo repositório no Debian13 KDE Plasma. Não transferir implementação ausente
como se fosse apenas homologação Linux.

## Incremento concluído — planos de avaliação

- Migração011: planos, revisões, etapas, vínculos imutáveis de execução/evidência.
  Reutiliza autorização/manifesto/hash revisado; não cria aprovação paralela.
- API cria/lista/revisa/consulta;25 etapas,100 revisões, últimos100 resultados
  com aviso de truncamento. SHA-256 canônico, parentHash, locks e FKs protegem
  história e isolamento de organização/projeto/ativo.
- static.scan integra etapa exata, validação, análise, job e evidências em uma
  transação. Revogação/substituição não atravessa esse despacho. Falha de
  preservação desfaz tudo; resultados antigos não recebem autorização retroativa.
- Tela Avaliações cria/revisa/executa análise estática, consulta história e exporta
  relatórios. Outros oito perfis apenas planejáveis; vínculos ainda pendentes.
- Corrigidos UUID canônico antes do hash, tipos nulos, truncamento na interface,
  estado ao trocar organização e leitura de histórico serializada com escrita.

## Validação

- TypeScript/build web passaram (44 módulos).
- Suíte JS com Python real:179 passaram,0 falhas,1 skip POSIX no Windows.
- Planos:18 API+3 core passaram;18 API também em PostgreSQL18 nativo/runtime
  restrito. Após ajuste final da leitura sob lock,18 API passaram novamente.
- Restore:41 tabelas idênticas,11 migrações,17 planos,21 revisões,22 etapas,
  10 execuções/vínculos,34 evidências,138 eventos; auditoria íntegra.
- QA navegador: criação/revisão, análise real estática, exportações/hashes,
  revogação,390px, resposta antiga descartada na troca de organização, sem erros
  de console. Truncamento testado com resposta sintética identificada.
- CI anterior dff15a3 passou Windows2022/Ubuntu24.04, run40568763223.
  CI deste incremento será registrada após envio; não presumir resultado.

Logs .sentinel/assessment-*.log; capturas/JSON .sentinel/qa. Ver VALIDATION_REPORT.
Rust/Python isolados históricos não repetidos localmente: fontes inalteradas.
Debian/Kali/QEMU e serviços não homologados. Nenhuma varredura de rede realizada.

## Base preservada

Guia26 seções/7 fontes/563 títulos; React/Fastify/PostgreSQL; fundador/MFA/
recuperação; clientes/projetos/ativos; PolicyGate; autorizações com prova cifrada,
perfis/limites, revisão, manifesto exato IPv4/portas/exclusões e revogação;
evidências cifradas/hashes/auditoria. Rust HMAC/FIM explícito/baseline/replay,
sem alegar EDR completo. Casos/relatórios; SecureFix CÓPIA SSH no banco; RiskGraph.
Análises offline/perícia PCAP/PCAPNG/SQLite/plist; ZIP em quarentena sem executar,
extrair ou acessar rede (16MiB original,512 entradas/64MiB expandidos).

## Próximo passo concreto

1. Integrar archive.inspect ao plano existente: autorização exata antes do worker,
   job/evidência/falhas e painel. Reutilizar assessment-plans.ts/imports.ts;
   não refazer plano/ZIP. Somente static.scan já está integrado.
2. Fase2: TAR/TAR.GZ após esse vínculo; depois URL/Git com escopo exato,
   SSRF/DNS/redirects/limites. Gobuster começa por importação offline delimitada.
3. Fase3: ProofLab sobre plano/importação, isolamento, teste reproduzível,
   correção na cópia, reteste comparável e relatório; SOC sintético não encerra fase3.
4. Seguir fases4–12. Fila recuperável, cancelamento supervisionado, cotas/CPU/RAM,
   demais vínculos/executores, Evidence Fusion, Blue/Purple e relatórios pendentes.
   Contratos/parsers/API/UI portáteis ficam no Windows. Linux SUID/SGID, Auditd/
   Suricata reais, serviços e isolamento QEMU/KVM/Kali exigem Debian. Revogar
   permissão não significa interromper um processo já iniciado.

## Ambiente e transferência

Privado autorizado: https://github.com/securityMaker488/isee-sentinel; main,
origin HTTPS conferido, GCM autorizado. Conferir status/HEAD/remoto ao retomar.
Credenciais/bancos/dumps/.sentinel/dependências não entram no Git. Pacotes antigos
são históricos; usar commit sincronizado ou bundle correspondente.

QA dedicado work/postgres-validation,127.0.0.1:55432; servidor sintético4311.
Conferir processos e encerrar temporários ao terminar. Nunca alterar PostgreSQL
preexistente5432. Não alterados Windows, partições, bootloader, firmware, firewall,
GPU ou Kali. CONTINUIDADE e planos anteriores são históricos; este checkpoint
orienta a retomada. Não depender da conversa no Debian.
