# Estado do projeto — 26/10/2026

## Retomada obrigatória

Guia funcional: docs/ESPECIFICACAO-V6.9.txt + complemento multiplataforma.
Precedência e hashes: docs/PROMPTS-REGISTRY.md. Retomar deste checkpoint e da
fila do ROADMAP.md, sem reler blocos grandes já revisados. Corrigir erros no
escopo encontrado. O usuário pediu terminar o possível no Windows antes de
migrar; a plataforma inteira e a etapa Windows ainda NÃO estão100% concluídas.

## Concluído neste incremento

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
- 113 testes JS/TypeScript passaram, incluindo Python real positivo/negativo.
- Rust18; Python integridade8+1skip Unix; Python perícia16; Python ZIP12;
  guarda do repositório3. Total dessas suítes:170pass e1skip.
- PostgreSQL nativo com runtime restrito: ZIP6 e perícia5 passaram; agentes6
  haviam passado no checkpoint anterior.
- Rust real → API → baseline → divergência → alerta → revogação passou.
- Backup/restore comparou34 tabelas do banco sintético,8 migrações e auditoria.
- Browser completo passou: correção/rollback, análises, ZIP, perícia, grafo,
  download, contexto de empresa/projeto, tela estreita e console sem erros.
- Correções encontradas: UUID de agente malformado; rótulos acessíveis; teto de
  requisições do painel insuficiente. Login continua limitado separadamente.
- Inventário atualizado e npm audit sem vulnerabilidades reportadas na consulta.

Detalhes, limitações e reprodução: VALIDATION_REPORT.md e TESTING.md.
Nenhuma varredura externa, alteração de sistema de cliente ou publicação ocorreu.
CI Windows/Ubuntu preparada, mas não executada. Debian não foi homologado.

## Próxima tarefa concreta no Windows

1. Fundação/Fase1: ampliar Authorization Manager com responsável, evidência de
   autoridade, vínculo de projeto e limites por avaliação. Definir contrato e
   negar parâmetros/limites sem executor correspondente. Preservar escopos atuais
   por ativo; incluir testes de revogação, separação de empresa e alteração de risco.
2. Fase2: estender Universal Import Lab a URL/Git/TAR por adaptadores separados;
   URL exige defesa SSRF, DNS/redirect/limites e associação exata ao alvo autorizado.
   ZIP já implementado não precisa ser refeito. Integrar plano de avaliação real.
3. Fase3: ProofLab completo, aplicação local isolada, avaliação reproduzível,
   correção na cópia, reteste comparável e relatório. Validar isolamento antes
   de iniciar aplicação desconhecida. SOC sintético não encerra essa fase.
4. Prosseguir fases4–12 conforme dependências. Não criar centenas de módulos
   vazios nem declarar as lacunas portáteis como dependência do Debian.

## Continuidade e ambiente

AGENTS.md, ROADMAP.md, MODULE_STATUS.md e matriz são registros versionáveis.
Git local emmain, sem remoto; GitHub CLI não encontrado. Sem push/publicação.
GITHUB-PRIVATE.md contém procedimento manual. Pacote de desenvolvimento e Git
bundle locais permitem transferir código sem transportar credenciais ou bancos.
ZIP V6.5 é histórico; usar entrega V6.9 quando registrada na pasta outputs.

Windows10Pro; Node24.21.0; Python3.11.9; Rust/Cargo1.98.1 observados. Não alterados
partições, boot, Windows, GPU, Kali, firewall ou serviço PostgreSQL preexistente5432.
Os processos temporários usados foram QA4311 e cluster work/postgres-validation
em55432. Conferir se estão ativos antes de reutilizar; nunca parar serviço5432.
Dumps/credenciais de teste estão em work ou .sentinel, fora do Git/pacote.

docs/CONTINUIDADE.md conserva o histórico. Este checkpoint substitui suas antigas
instruções de retomada. Consulte o último commit local para identificar a revisão;
não pressupor que o histórico desta conversa acompanhará a migração.
