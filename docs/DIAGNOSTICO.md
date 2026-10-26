# Diagnóstico e migração planejada

Data da observação: 23/10/2026. Sistema acessível: Windows 10 Pro 10.0.19045. Alvo V6.5: Debian 13 Stable + KDE Plasma em dual boot com Windows. O Arch relatado pelo operador não foi inspecionado nem substituído. A migração ainda não aconteceu nesta sessão. O plano seguro da fase 0 está em `FASES-V6.5.md`.

| Dado | Origem | Interpretação permitida |
|---|---|---|
| i7-7700HQ, 4 cores/8 threads | Consulta local Windows | Base de dimensionamento CPU; não é benchmark |
| 16.658.020 KiB RAM; 6.071.800 KiB livres | Consulta local Windows | Disponibilidade pontual; muda com os processos |
| GTX 1050 e Intel HD 630 | Consulta local Windows | Adaptadores detectados; driver reportou aproximadamente 4 GiB/1 GiB |
| SSD Kingston A400, aproximadamente 480 GB comerciais | Declaração do operador V6.3 | Capacidade/modelo do disco físico ainda não verificados aqui |
| C: 239.345.352.704 bytes total; 81.516.568.576 livres | Consulta do volume lógico Windows | Volume C não é sinônimo do SSD físico; não concluir falta de capacidade, layout ou espaço livre em outras partições |
| HD externo de 1 TB | Declaração do operador V6.5 | Capacidade física, filesystem, saúde e conteúdo não inspecionados; não montado, formatado ou alterado |
| Virtualização firmware habilitada | Consulta local Windows | KVM/libvirt e isolamento de VM não demonstrados |
| Node 24.21.0, npm 11.19.0, Python 3.11.9, Git 2.56.0.windows.2 | Comandos de versão | Ferramentas disponíveis no Windows; não prova configuração Debian |
| PostgreSQL serviço18 em execução | Inventário de serviços | Serviço existente preservado; testes usam instância temporária separada quando registrado |
| WSL sem distribuição confirmada | Comando devolveu ajuda | Não declarar Debian/Arch instalado no WSL |

No Debian real, execute `bash scripts/diagnose-linux.sh` sem sudo. Registre a saída em local privado e compare com os requisitos antes de instalar ferramentas. O script inclui versões Rust/Cargo quando disponíveis, sem instalar toolchain. Não coletar seriais, credenciais ou conteúdo de arquivos pessoais para dimensionamento.

Debian 13 é alvo confirmado nas [informações oficiais trixie](https://www.debian.org/releases/trixie/). O pacote Node padrão trixie consultado está na linha 20; o projeto exige24. Usar binário oficial24 verificado com assinatura/checksum e diretório específico é uma opção a homologar, sem misturar pacotes de Ubuntu, sid ou outra versão Debian. [Pacote Debian Node](https://packages.debian.org/trixie/nodejs).

GTX 1050/Pascal requer avaliação específica: a NVIDIA informa incompatibilidade com seus módulos kernel open e identifica580 como última família Linux para Pascal. Isso não autoriza instalar um pacote arbitrário, não prova compatibilidade com o kernel Debian e não define performance de LLM. Confira identificação PCI, kernel, pacote disponível e advisories no momento da migração. [Arquiteturas NVIDIA](https://developer.nvidia.com/blog/nvidia-transitions-fully-towards-open-source-gpu-kernel-modules/), [suporte legado](https://nvidia.custhelp.com/app/answers/detail/a_id/3142/).

Kali com 2 vCPUs/4 GiB é uma hipótese inicial do prompt, não alocação realizada. Com a memória livre observada no Windows, reserve margem para host, navegador e backend; valide novamente no Debian e ligue um laboratório por vez. A rede virtual precisa ser isolada, sem bridge para infraestrutura comercial e sem roteamento externo não autorizado.

Não há nesta entrega reparticionamento, formatação, alteração de bootloader, instalação de driver, migração de sistema ou mudança do HD externo. A próxima ação executável é coletar o diagnóstico no Debian quando disponível; backups verificados e inventário do layout antecedem qualquer futura migração autorizada.
