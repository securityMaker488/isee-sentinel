# Estado do projeto — 26/10/2026

## Retomada obrigatória

Guia funcional: docs/ESPECIFICACAO-V6.9.txt + complemento multiplataforma.
Precedência e hashes: docs/PROMPTS-REGISTRY.md. Retomar deste checkpoint e da
fila do ROADMAP.md, sem reler blocos grandes já revisados. Corrigir erros no
escopo encontrado. O usuário pediu terminar o possível no Windows antes de
migrar; a plataforma inteira e a etapa Windows ainda NÃO estão100% concluídas.

## Concluído neste incremento

Authorization Manager conectado à tela Autorizações, migração009 e PolicyGate.
Rascunho imutável registra responsável, comprovação cifrada, projeto, ativos,
vigência, modo/risco, perfis e limites. Aprovação explícita vincula o hash revisado,
substitui os escopos anteriores e torna o ativo gerenciado. Revogação não permite
retorno ao escopo legado. Nove perfis conferem bytes/portas reais nos executores;
alterações de risco/limites exigem nova revisão. Ativos legados preservados até
adesão ao fluxo. Não há execução crítica no host nem cancelamento instantâneo.

Fundação privada React/Fastify/PostgreSQL, MFA, recuperação do fundador,
organizações/projetos/ativos/escopos, evidências cifradas e auditoria preservadas.
Agente Rust real conecta por HMAC, monitora arquivo explícito com baseline
aprovada, detecta alteração e respeita revogação/replay/idempotência.

Casos têm notas cifradas, evidências, estados e relatório. SecureFix aprova,
aplica, verifica e restaura CÓPIA de SSH no banco; não altera o host.
Análises offline: dependências/CycloneDX, NmapXML/HAR, SARIF, IAM/S3,
identidades, configuração de IA, PE/ELF/scripts, timelines e OpenAPI JSON3.0/3.1.
RiskGraph está conectado à API e ao painel, com limites e contexto por empresa.
Perícia Python/API/painel cobre PCAP/PCAPNG/SQLite/plist fornecidos.

Universal Import Lab: ZIP até16MiB em quarentena cifrada, projeto herdado do
ativo, até512 entradas e64MiB expandidos; hashes/CRC/caminhos/links/colisões e
expansão verificados. Identifica tecnologias por indícios, sem extrair, executar
ou acessar rede. API, migração008, worker e UI conectados. ZIP64, descriptors,
arquivos compactados internos, URL, Git e demais formatos não são suportados.
O adaptador Nmap tem limites e testes injetados, mas Nmap real não foi homologado.

## Verificações encerradas

- Setup Windows completo passou: dependências fixadas, build web/Rust e doctor.
- 146 testes JS/TypeScript passaram, incluindo 13 novos de política, 20 do
  Authorization Manager e Python real positivo/negativo.
- Rust18; Python integridade8+1skip Unix; Python perícia16; Python ZIP12;
  guarda do repositório3 no checkpoint anterior, fontes inalteradas. Não repetidos
  neste incremento; o total histórico anterior era170pass e1skip.
- PostgreSQL nativo com runtime restrito: ZIP6 e perícia5 passaram; agentes6
  haviam passado no checkpoint anterior.
- Rust real → API → baseline → divergência → alerta → revogação passou.
- Authorization Manager no PostgreSQL nativo com runtime restrito:20 passaram.
- Backup/restore atual comparou36 tabelas do banco sintético,9 migrações e
  auditoria; incluiu30 autorizações estruturadas e31 vínculos de ativos.
- Browser completo passou: correção/rollback, análises, ZIP, perícia, grafo,
  download, contexto de empresa/projeto, tela estreita e console sem erros.
- Correções encontradas: UUID de agente malformado; rótulos acessíveis; teto de
  requisições do painel insuficiente. Login continua limitado separadamente.
- Inventário atualizado e npm audit sem vulnerabilidades reportadas na consulta.

Detalhes, limitações e reprodução: VALIDATION_REPORT.md e TESTING.md.
Nenhuma varredura externa, alteração de sistema de cliente ou publicação ocorreu.
CI Windows/Ubuntu preparada, mas não executada. Debian não foi homologado.

## Próxima tarefa concreta no Windows

1. Fundação/Fase1: recorte do Authorization Manager concluído e validado.
   Prosseguir no contrato do plano de avaliação, catálogo versionado e vínculo
   de resultados; fila geral de jobs permanece pendente. Não reimplementar o
   ciclo de autorização já entregue.
2. Fase2: estender Universal Import Lab primeiro a TAR/TAR.GZ, depois URL/Git,
   por adaptadores separados e perfis explícitos;
   URL exige defesa SSRF, DNS/redirect/limites e associação exata ao alvo autorizado.
   ZIP já implementado não precisa ser refeito. Integrar plano de avaliação real.
3. Fase3: ProofLab completo, aplicação local isolada, avaliação reproduzível,
   correção na cópia, reteste comparável e relatório. Validar isolamento antes
   de iniciar aplicação desconhecida. SOC sintético não encerra essa fase.
4. Prosseguir fases4–12 conforme dependências. Não criar centenas de módulos
   vazios nem declarar as lacunas portáteis como dependência do Debian.

## Continuidade e ambiente

AGENTS.md, ROADMAP.md, MODULE_STATUS.md e matriz são registros versionáveis.
Git local emmain. Repositório privado securityMaker488/isee-sentinel criado em
26/10/2026 e origin configurado por autorização do operador. Consultar
GITHUB-PRIVATE.md para o estado da autenticação/sincronização. Pacote e Git
bundle locais permitem transferir código sem transportar credenciais ou bancos.
Os pacotes V6.5 e V6.9-windows-dev anteriores são históricos e não incluem este
incremento de autorização; usar o último commit sincronizado ou bundle atualizado.

Windows10Pro; Node24.21.0; Python3.11.9; Rust/Cargo1.98.1 observados. Não alterados
partições, boot, Windows, GPU, Kali, firewall ou serviço PostgreSQL preexistente5432.
Os processos temporários usados foram QA4311 e cluster work/postgres-validation
em55432. Conferir se estão ativos antes de reutilizar; nunca parar serviço5432.
Dumps/credenciais de teste estão em work ou .sentinel, fora do Git/pacote.

docs/CONTINUIDADE.md conserva o histórico. Este checkpoint substitui suas antigas
instruções de retomada. Consulte o último commit local para identificar a revisão;
não pressupor que o histórico desta conversa acompanhará a migração.
