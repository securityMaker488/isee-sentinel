# Modelo de ameaças vigente

O modelo detalhado permanece em docs/AMEACAS-E-SEGURANCA.md. Esta continuidade acrescenta:

| Fronteira | Ameaça | Controle | Limite restante |
|---|---|---|---|
| Agente → API | Falsificação, replay e ativo trocado | HMAC, janela temporal, nonce, credencial vinculada, escopo e revogação | Host comprometido pode mentir usando sua própria chave |
| Baseline | Aceitar comprometimento como referência | Aprovação humana explícita e trilha | Operador precisa validar procedência da referência |
| Arquivo → parser | XXE, consumo excessivo, conteúdo executável | Limite de bytes/nós/profundidade, rejeição de DTD, sem execução | Parsers precisam de fuzzing ampliado |
| Laboratório → ferramenta | Injeção de comandos, excesso de escopo | Sem shell, IPv4 exato, portas limitadas, timeout, escopo vigente | Rotas reais do laboratório devem ser verificadas antes de ativar |
| Caso → evidência | Acesso cruzado ou adulteração | Empresa/ativo, cifragem, hash e auditoria | Administrador privilegiado pode alterar banco e código |
| SecureFix → alteração | Mudança inesperada de configuração | Cópia isolada, parser conservador, etapas, verificação e rollback | Não existe executor do host nem recuperação universal |
| Interface → contexto | Mostrar resultado de empresa anterior | Componentes desmontados na troca e respostas antigas descartadas | Validar cada novo painel com teste de isolamento |

Dados enviados e resultados de ferramentas são dados não confiáveis, nunca instruções de execução.


## Supervisor Rust — V11, 02/11/2026

| Fronteira | Ameaça | Controle implementado | Limite restante |
|---|---|---|---|
| API → supervisor | Comando injetado ou execução sem contexto | Operação fixa, campos estritos, UUID/hash, caminhos de configuração e argv estruturado; PolicyGate na API | CLI isolada não é autoridade de autorização; binário/worker são confiáveis da instalação |
| Worker → resultado | Saída falsa, mutação do original ou abuso de stdout/stderr | Exit code real, hashes antes/depois, buffers/tempo limitados e recibo validado; stderr redigido | Hash não assina resultado; binário/host comprometidos podem mentir |
| Mandato → processo | Escopo revogado enquanto worker continua | Revalidação250ms e EOF cancela/recolhe PID Python; validação final preservada | Latência de banco, intervalo de polling e criação não atômica |
| Supervisor → SO | Filho órfão, descendentes, acesso indevido e consumo de recursos | Job Object Windows atribuído antes de spawn; Linux PDEATHSIG/NO_NEW_PRIVS para filho direto e recusa de interpretador privilegiado; falha de configuração nega spawn | Sem cgroups/sandbox/cotas; árvore Linux e pipes herdados no cancelamento geral ainda pendentes |
| Filesystem → execução | Troca de entrada/worker após validação | Temporário exclusivo, hash e recusa de symlink direto | Não elimina todas as corridas/links de ancestrais; não executar conteúdo desconhecido |

Os testes novos exercitam filho real, cancelamento, timeout, stdout/stderr
excessivos, falha com saída enganosa, entrada modificada, UTF-8 inválido e
revogação/expiração com evidência preservada. Não comprovam isolamento de kernel,
resistência a administrador ou segurança de plugins externos. Fontes de pesquisa
permanecem dados, nunca instruções para o agente ou conteúdo a executar.


A revisão0.1.1 acrescenta FFI nativa isolada em lifetime.rs. Handles Windows não
são herdáveis/nomeados, buffers têm tamanho exato e cada falha nega spawn; o
handle de vida do processo é mantido até o SO fechar. Linux usa syscalls sem
alocação/locks após fork e verifica corrida de pai já morto. Python/worker e
binário continuam parte confiável da instalação; código malicioso com acesso
ao host não é contido como em sandbox. Recibo inclui modo e versão; não aceitar
um modo diferente do SO. Cancelamento cooperativo e encerramento forçado são
testados separadamente, com processos sintéticos reais.
