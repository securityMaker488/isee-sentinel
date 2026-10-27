# Estado do projeto — 27/10/2026

## Retomada obrigatória — uma linha de desenvolvimento

Requisitos: [guia mestre consolidado](docs/GUIA-MESTRE-CONSOLIDADO.md).
Fila única: [ROADMAP.md](ROADMAP.md). Fontes/hashes: docs/PROMPT-COVERAGE.json.
Ao receber “continue”, usar este checkpoint e somente os arquivos da tarefa.
Não repetir auditoria ampla nem reler todos os prompts. Preservar implementações
funcionais e corrigir erros encontrados. A ordem global é V6.9 fases 0–12;
AttackLab 1–6 são etapas internas, não um segundo projeto.

**Posição atual: fase global 1 / núcleo seguro AttackLab A2, parcialmente entregue.**
Terminar o trabalho possível no Windows antes de Debian. A etapa Windows e a
plataforma inteira ainda NÃO estão 100% concluídas.

## Incremento concluído em 27/10

- Guia único com 26 seções reúne V5.0/V6.3/V6.5/V6.6/V6.9 e complementos
  multiplataforma/AttackLab. Sete fontes integrais preservadas; 563 títulos
  indexados, precedência resolvida. Não é declaração de cobertura funcional.
- Manifesto versão 1 inclui pares ativo/IPv4/portas e exclusões no pedido revisado.
  Hash esquema 2 e migração 010 preservam termos imutáveis; exclusão prevalece.
  Cadastro/despacho Nmap exigem endereço exato, portas, mesma revisão e vigência.
  Escopos antigos sem manifesto não autorizam rede; demais perfis mantêm a
  política existente. Scans registram mandato/hash com FKs e histórico imutável.
- Tela Autorizações cria, mostra e exporta manifesto; aprovação segue explícita.
  Não foi criado consentimento paralelo nem homologado Nmap real.
- Perícia resolve o Python configurado por caminho real, como o worker ZIP.
  Corrige rejeição de links simbólicos observada na CI Ubuntu.

## Validação deste incremento

- TypeScript e build React/Vite passaram.
- Suíte JS completa com Python real: 158 passaram, 0 falhas, 1 skip POSIX no Windows.
- Testes focados autorização/laboratório: 50 passaram. Manifesto puro também
  testado na suíte completa. Nmap é substituto injetado, sem varredura.
- Authorization Manager em PostgreSQL 18 nativo com runtime restrito: 26 passaram.
- Backup/restore: 36 tabelas idênticas, 10 migrações, 37 mandatos, 39 vínculos de
  ativos, 3 scans de laboratório e 225 eventos de auditoria; cadeias válidas.
- Navegador: rascunho com manifesto, downloads, revisão/aprovação, endereço
  permitido, exclusões/fora de escopo negados, bytes/perfis, revogação,
  tela de 390 px e console sem erros passaram.
- CI anterior 749bf63: Windows2022 passou; Ubuntu24.04 passou no doctor corrigido,
  mas falhou em 1/146 testes por symlink Python. Correção validada localmente;
  confirmar o resultado remoto deste incremento em Actions.

Logs em .sentinel/manifest-*.log; detalhes e históricos em VALIDATION_REPORT.md.
Rust/Python isolados anteriores não foram repetidos localmente: fontes inalteradas.
Debian/Kali/QEMU não foram homologados.

## Base funcional preservada

React/Fastify/PostgreSQL; fundador/MFA/recuperação; clientes/projetos/ativos;
PolicyGate; Authorization Manager com responsável/prova cifrada/aprovação/perfis/
limites/revogação; evidências cifradas/hashes/auditoria. Agente Rust real com
HMAC/FIM de arquivo explícito, baseline aprovada, divergência e proteção contra
replay; não é EDR completo nem serviço Linux homologado. Casos/notas/estados/
relatórios; SecureFix aprova/aplica/verifica/restaura CÓPIA de SSH no banco, sem
alterar host. RiskGraph integrado com limites.

Análises offline: dependências/CycloneDX, NmapXML/HAR/SARIF, IAM/S3/identidade/IA,
PE/ELF/scripts/timelines/OpenAPI JSON 3.0/3.1. Perícia PCAP/PCAPNG/SQLite/plist.
ZIP até 16 MiB, 512 entradas/64 MiB expandidos, quarentena cifrada e inspeção sem
extração/execução/rede. ZIP64/descriptors/aninhados e outros formatos pendentes.

## Próximo passo concreto — retomar aqui

1. Ainda na fase 1, implementar **plano de avaliação versionado** que referencie
   autorização revisada, projeto/ativos, perfis existentes e resultados. Reutilizar
   mandato/manifesto; definir contratos e vínculos com jobs/evidências sem catálogo
   de executores fictícios. Cancelamento supervisionado, limites de recursos e
   fila recuperável continuam pendentes; tratar as dependências necessárias ao
   fluxo. Revogação não significa interrupção imediata de processo iniciado.
2. Fase 2: TAR/TAR.GZ após contrato do plano; depois URL/Git com escopo exato,
   SSRF/DNS/redirect/limites. Não refazer ZIP. Gobuster começa por importação
   offline delimitada na mesma linha de importação/assessment.
3. Fase 3: ProofLab integrado ao plano/importação, isolamento, teste reproduzível,
   correção na cópia, reteste comparável e relatório. SOC sintético não encerra fase 3.
4. Seguir fases 4–12 e dependências. Evidence Fusion amplia vínculos/timeline/
   grafo existentes. Blue/Purple começa por normalizadores, metadados e resultados
   manuais. Auditoria Linux, agentes/serviços, Suricata/Auditd reais e isolamento
   Kali/QEMU exigem homologação Debian; contratos/API/UI portáteis ficam no Windows.

## Ambiente, Git e transferência

Repositório privado autorizado: https://github.com/securityMaker488/isee-sentinel.
Branch main; origin HTTPS observado; GCM autorizado e autenticado. Conferir git
status e igualdade HEAD/remoto ao retomar. Pacotes antigos são históricos; usar
commit sincronizado ou bundle com manifesto da revisão correspondente.
Credenciais, bancos e dumps em work/.sentinel não entram no Git.

Windows10Pro; Node24.21.0; Python3.11.9; Rust/Cargo1.98.1 no checkpoint.
Cluster de teste exclusivo work/postgres-validation em 127.0.0.1:55432 e QA
sintético em 4311: conferir processos antes de reutilizar e encerrar ao terminar.
Nunca parar/alterar PostgreSQL preexistente5432. Não alterados Windows, partições,
bootloader, firmware, firewall, GPU ou Kali.

CONTINUIDADE e planos anteriores são históricos; este checkpoint determina a
retomada atual. Não depender da conversa para continuar no Debian.
