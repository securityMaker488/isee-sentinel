# Estado do projeto — 02/11/2026

## Retomada — uma linha de desenvolvimento

Guia: docs/GUIA-MESTRE-CONSOLIDADO.md. Fila: ROADMAP.md. Fontes/hashes:
docs/PROMPT-COVERAGE.json. Ao receber “continue”, retomar este checkpoint e
somente os arquivos da tarefa. Não repetir auditoria ampla nem reler os prompts.
Ordem global V6.9 fases0–12; AttackLab A1–A6 internas.

**Posição: fase global2 / AttackLab A2, parcialmente entregue.** Fundação de
planos e autorizações reutilizada; importação ZIP/TAR/TAR.GZ vinculada ao plano
entregue neste recorte. Windows e plataforma inteira ainda NÃO estão100%
concluídos. Completar desenvolvimento portátil aqui; quando restarem somente
tarefas dependentes de Linux, parar e continuar pelo GitHub no Debian13 KDE.
Não transferir implementação ausente como se fosse apenas homologação Linux.

## Incremento concluído — inspeção vinculada ao plano e TAR

- archive.inspect integra etapa/revisão exatas, job e original cifrado na mesma
  transação. Autorização revalidada na preservação, antes do worker e na aceitação
  do resultado. Revogação/expiração/substituição detectadas negam despacho ou
  conclusão, sem atribuição retroativa. Original permanece se a inspeção falhar.
- Migração012: identidade da importação/mandato/hash imutáveis e FKs por ativo.
  Migração013: amplia formatos. Nenhuma migração001–011 foi alterada.
- Worker1.1: ZIP e TAR/TAR.GZ USTAR, formato explícito, hashes/metadados sem
  extrair/executar/conectar à rede.16MiB original,512 entradas,8MiB por entrada,
  64MiB de conteúdo, razão100. Recusa PAX/GNU/sparse/links/dispositivos e membros
  gzip concatenados; limites detalhados em docs/IMPORT-ARCHIVE-WORKER.md.
- Telas Avaliações/Import Lab enviam três formatos e exportam registros reais.
  Falhas atualizam o resultado do plano e mantêm evidência. Sem seleção de etapa,
  o formulário pede a seleção antes de apresentar campos do arquivo.
- static.scan segue integrado; sete outros perfis somente planejáveis.
  Revogação não mata processo já iniciado. Cancelamento supervisionado, fila
  recuperável e cotas acumuladas ainda pendentes.

## Validação local deste incremento

- TypeScript/build passaram,44 módulos. Suíte JS com Python real:185 passaram,
  0 falhas,1 skip POSIX no Windows. Python/imports:24 passaram.
- Importações:12 API passaram também em PostgreSQL18 nativo/runtime restrito,
  incluindo processo Python real ZIP/TAR/TAR.GZ e recusas.
- Backup/restore:41 tabelas idênticas,13 migrações,17 importações/jobs,9 planos/
  revisões/etapas/execuções/vínculos,26 evidências e87 eventos; auditoria íntegra.
- QA navegador de arquivos e regressão estática passaram: upload real, revisão,
  exportação, falha preservada, revogação,390px e troca de organização no roteiro
  estático. Último ajuste de apresentação recompilado e QA de arquivos repetido.
- Logs .sentinel/archive-*.log; capturas/JSON .sentinel/qa. VALIDATION_REPORT.md
  mantém o histórico. Rust e workers não alterados fora de imports não foram
  repetidos localmente. Nova CI ainda não verificada neste checkpoint.

## Próximo passo concreto

1. Fase2: projetar/implementar importação URL como adaptador separado, integrado
   ao plano e evidência. Primeiro contrato de autorização para URL exata,
   esquemas/portas/endereço resolvido, bloqueio SSRF/DNS/redirects e limites de
   bytes/tempo. Usar servidor sintético local no teste; nenhuma busca arbitrária
   externa deve nascer de permissões amplas. Não reutilizar o manifesto IPv4 de
   Nmap como autorização implícita para HTTP. Não reescrever ZIP/TAR ou planos.
2. Depois, importação Git com escopo/transporte/submódulos/hooks/limites próprios.
   Gobuster começa por importação offline delimitada. Manter um fluxo por vez.
3. Fase3: ProofLab sobre plano/importação, isolamento, teste reproduzível,
   correção em cópia, reteste comparável e relatório. SOC sintético não encerra3.
4. Seguir fases4–12. Contratos/parsers/API/UI portáteis continuam no Windows.
   Linux SUID/SGID, Auditd/Suricata reais, serviços e QEMU/KVM/Kali exigem Debian.
   As fases anteriores continuam parciais onde houver dependências registradas.

## Base e continuidade

Guia26 seções/7 fontes/563 títulos; React/Fastify/PostgreSQL, fundador/MFA,
clientes/projetos/ativos, PolicyGate, mandatos com comprovação e manifesto exato,
evidências cifradas e auditoria. Rust HMAC/FIM finito, casos, análises offline,
SecureFix CÓPIA SSH no banco, RiskGraph e perícia PCAP/PCAPNG/SQLite/plist mantidos.
Não presumir EDR completo, pentest geral, implantação Linux ou isolamento de VM.

Privado autorizado: https://github.com/securityMaker488/isee-sentinel; main,
origin HTTPS e privacidade confirmados pela API em02/11. GCM autorizado.
Credenciais/bancos/dumps/.sentinel/dependências não entram no Git. Pacotes antigos
são históricos; usar o commit sincronizado. Não depender da conversa no Debian.

QA dedicado work/postgres-validation em127.0.0.1:55432 e servidor sintético4311
encerrados após os testes em02/11. Conferir processos antes de reutilizar.
Nunca alterar PostgreSQL preexistente5432. Windows/partições/bootloader/firmware/
firewall/Kali não foram alterados. CONTINUIDADE e planos anteriores são históricos.
