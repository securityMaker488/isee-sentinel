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
