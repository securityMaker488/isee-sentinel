# Fases 0–10 — execução e gates da V6.5

Especificação vigente: V6.5, 23/10/2026. O comando final pede começar pelo backend, PostgreSQL, autenticação, Command Center e primeira função verificável. Essas entregas foram preparadas e testadas no Windows disponível. Isso não conclui a fase 0 nem valida Debian, partições, drivers, KVM ou systemd.

## Cronologia e estado

| Fase | Objetivo | Trabalho realizado / próximo gate | Estado |
|---|---|---|---|
|0 | Preparar Debian 13 KDE, preservar Windows, substituir Arch, validar boot/hardware | Diagnóstico Windows e roteiro somente leitura. Nenhuma partição, mídia de instalação, bootloader ou driver alterado | Pendente no Debian real |
|1 | Estação Git/Node/Python/Rust/PostgreSQL/testes | Runtimes Windows usados; Node 24 deve ser configurado separadamente do pacote padrão trixie20 | Preparação Windows; homologação Debian pendente |
|2 | Núcleo próprio, PostgreSQL, fundador, PolicyGate, auditoria e Command Center | Fatia integrada local; PostgreSQL nativo temporário separado e PGlite explícito para testes | Testado no escopo registrado; M4 pendente |
|3 | Agente Linux, ingestão, regra, alerta, persistência e UI | Regra de 5 falhas/5 min recebe eventos sintéticos autorizados e gera alerta real persistido; Rust/Python observam/validam arquivo offline | Parcial; ingestão autenticada do agente Linux e teste Debian pendentes |
|4 | SecureBuild genérico, dependências, segredos, auth/API e relatório | Regras estáticas limitadas e relatório; instalação de Firebase/Supabase não faz parte | Parcial; SCA/SAST/DAST abrangentes pendentes |
|5 | Podman rootless opcional e Kali QEMU/KVM isolado | Arquitetura e critérios de isolamento documentados | Planejado; nenhuma VM/contêiner instalado ou iniciado |
|6 | BarrierMatrix, DefenseFlow, RiskGraph, SecureFix, AutoDefense, Self-Healing, ResponseGrid | Catálogo de 14 camadas, avaliação estática, risco e detecção inicial | Parcial; executores de contenção/patch/recuperação planejados |
|7 | AttackLab/PurpleMatrix e investigação/forense | EvidenceChain de artefatos pequenos; protótipo de hash offline | Parcial; motores forenses, lab e análise dinâmica planejados |
|8 | Adaptadores externos opcionais | Fronteira SecureBuild External Backend Security Adapters documentada | M0; depende da base validada, sem integração externa |
|9 | Agente Windows, integrações nativas, empacotamento e recuperação | Núcleo e protótipo offline exercitados no Windows | Parcial; ETW/Event Log, instaladores e atualização segura planejados |
|10 | IdentityGuard, CloudShield, teste profundo e avaliação comercial | Módulos no inventário e critérios M0–M6 | M0; sem certificação ou comercialização |

## Fase 0: próxima coleta segura

O objetivo imediato é conhecer a topologia sem modificá-la. No Windows, estes comandos são somente leitura e não incluem número de série:

```powershell
# Identifica discos fisicos por numero, tamanho e particionamento.
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle, IsBoot, IsSystem
# Relaciona particoes a discos sem alterar tamanho, letra ou conteudo.
Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, Type
# Mostra volumes e espaco livre; nao monta volumes ausentes.
Get-Volume | Select-Object DriveLetter, FileSystem, Size, SizeRemaining, HealthStatus
```

No Linux já iniciado ou em mídia de avaliação preparada conscientemente, sem instalar:

```bash
# Identifica distribuicao e kernel.
cat /etc/os-release
uname -srmo
# Lista discos/particoes e pontos de montagem; nao monta nem formata.
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS
# Mostra o filesystem que contem a raiz do sistema em execucao.
findmnt -no SOURCE,FSTYPE,OPTIONS /
# Indica modo de boot observado; nao altera firmware nem entradas.
if [ -d /sys/firmware/efi ]; then printf 'Boot UEFI observado\n'; else printf 'UEFI nao observado nesta sessao\n'; fi
# Coleta recursos e versoes disponiveis, sem sudo ou instalacao.
bash scripts/diagnose-linux.sh
```

Não executar comandos de escrita como `mkfs`, `wipefs`, operações de partição, instalação de bootloader, alteração de firmware ou montagem do HD externo como parte dessa coleta. Saídas podem conter nomes de volumes: compartilhe apenas dados necessários, nunca chaves de recuperação de disco.

Antes de uma futura instalação autorizada: confirmar quais partições pertencem a Windows, Linux, EFI e recuperação; verificar backup/restauração dos dados e meios de recuperação do Windows; obter imagem Debian e conferir assinatura/hash pelos canais oficiais; registrar plano de alteração, caminho de retorno e o disco selecionado. A próxima aprovação de instalação deve apresentar esse plano concreto. Aqui não existe evidência suficiente para escolher números de partição ou destinos de escrita. [Informações oficiais Debian 13](https://www.debian.org/releases/trixie/).

## Camadas híbridas e limites de implantação

| Camada | Carga prevista | Critério antes de ativar |
|---|---|---|
| A Debian nativo | Núcleo, PostgreSQL local, Node, Rust, Python, motores e systemd | Runtime/driver suportado, contas de serviço, privilégios mínimos, backup restaurado e testes no host |
| B Podman rootless opcional | Workers leves e testes descartáveis autorizados | Imagem com procedência/digest, revisão de licenças, CPU/RAM/tempo/armazenamento limitados, rede mínima e montagens restritas |
| C Kali QEMU/KVM | Exercícios completos autorizados e kernel separado | KVM utilizável, rede isolada testada, compartilhamentos mínimos, snapshot recuperável e desligamento ao terminar |

Para Podman, o perfil futuro deve impedir `--privileged`, acesso ao socket de administração, montagem ampla de `/`, diretórios pessoais ou segredos. Adotar imagem por digest, usuário não privilegiado, capabilities reduzidas, filesystem somente leitura quando possível, volumes de entrada somente leitura e saída delimitada. `--network=none` é preferível para análise offline; acesso necessário exige allowlist e teste. Rootless não garante que todos os limites de cgroup estejam aplicados no host: verificar a efetividade antes da operação. Não foi gerado um comando de execução com imagem/digest inventados. [Referência oficial Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html).

Para Kali, 2 vCPUs/4 GiB e 40–60 GB expansíveis são hipóteses iniciais, não recursos alocados. Confirmar folga no Debian, crescimento do disco e custo dos snapshots. Rede libvirt sem encaminhamento é uma base de isolamento, mas ainda requer verificar caminhos guest→host, outras interfaces e regras do host. Não escolher NAT/bridge como sinônimo de isolamento. Sem pastas/clipboard compartilhados desnecessários; desligar a VM quando não estiver em uso. Contêiner e chroot não substituem VM para experimento que exija kernel próprio, e VM comum não garante contenção de malware. [Redes libvirt](https://libvirt.org/formatnetwork.html).

## Armazenamento e rede

SSD interno: sistemas, projeto ativo e PostgreSQL operacional; HD externo de 1 TB declarado: futuro backup/ISOs/arquivos de laboratório, após identificação e autorização. Nenhum dispositivo externo foi montado ou formatado. Não armazenar a única cópia de dado importante nele. Evidência sensível exige proteção e teste de recuperação, mesmo sendo sintética ou de laboratório.

O núcleo não exige conexão contínua após dependências instaladas. npm/crates, imagens, atualizações, bases de vulnerabilidades e adaptadores externos precisam de rede quando utilizados e devem declará-la. Podman, Kali, Firebase, Supabase e APIs pagas não são dependências da inicialização do Sentinel.

## Evidências de teste e promoção de maturidade

A V6.5 registrou 37 testes JS aprovados (17 core, 19 API, 1 configuração), além dos mesmos 19 casos API em PostgreSQL 18.6 nativo com papel runtime restrito. Backup/restauração em banco novo comparou 14 tabelas sem diferenças e validou a cadeia de auditoria. Rust registrou 9 e Python 8 com 1 caso Unix ignorado. O E2E final aprovou 12 passos, incluindo empresas, projetos, troca de contexto e isolamento, sem erros JavaScript ou de console; o favicon foi corrigido. O escopo exato e as limitações estão em `VALIDATION.md`. Essas evidências Windows não provam Debian, sensor residente ou validação independente. Nenhum módulo é promovido a M4–M6 com base apenas nesses números.
