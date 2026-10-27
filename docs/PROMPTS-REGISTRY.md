# Guias vigentes e memória portátil

Atualizado em 26/10/2026. A memória do projeto fica no próprio repositório;
não depende da conversa estar disponível em outra máquina.

1. **Guia funcional principal:** ESPECIFICACAO-V6.9.txt, recebido em 25/10/2026.
   SHA256: b2ceb4166505a65158cb6d292fa2b60c3271b1b81d00b751a7590c9739b73fbd.
   Cópia integral, byte a byte, do anexo do operador. Define fases 0–12,
   Universal Import Lab, ProofLab e o padrão obrigatório de engenharia da seção 53.
   A evolução e as lacunas estão em EVOLUCAO-V6.9.md; execução em ../ROADMAP.md.
2. **Complemento:** COMPLEMENTO-MULTIPLATAFORMA.txt, recebido em 25/10/2026.
   SHA256: 8f0f61bb044bb9124b620ff5baeeed2d636c0e85e54f87a5ae23a30847a18261.
   Acrescenta memória AGENTS/PROJECT_STATE, Git privado, scripts reproduzíveis,
   CI e continuidade Windows↔Debian. Permanece válido onde compatível com V6.9;
   não autoriza publicação automática nem instalação destrutiva do sistema.
3. **Guia funcional histórico:** ESPECIFICACAO-V6.6.txt, recebido em 24/10/2026.
   SHA256: 31cecb4835cc7b640bfdfbedc79247af9d9b745fd71d1fd24e290517c8e04bff.
   Preservado para rastreabilidade do portfólio e detalhes compatíveis. V6.9 tem
   precedência em conflitos e substitui sua numeração de fases 0–16.
4. **Preferência do operador:** ao pedir continuação, retomar o ponto registrado
   sem revisar novamente blocos grandes já revisados. A inspeção de portabilidade
   usa inventário, registros e buscas dirigidas; novas alterações são verificadas.
5. **Complemento AttackLab Evidence Fusion & Purple Validation Engine:**
   COMPLEMENTO-ATTACKLAB-EVIDENCE-FUSION.md, recebido no chat em26/10/2026.
   SHA256: 2b8beb5ca7d796bac40582b4909034a750dab9b050c10ce430bb740cbe36403b.
   Transcrição integral do texto com espaçamento de Markdown normalizado em UTF-8
   e LF; o hash identifica este arquivo, não bytes originais de um anexo.
   Acrescenta operação/alvos/exclusões, descoberta controlada, auditoria Linux,
   fusão de evidências e validação Blue/Purple. Não substitui V6.9 nem antecipa
   mudança de sistema. Suas fases1–6 são locais ao módulo; plano e correspondência
   em ATTACKLAB-EVIDENCE-FUSION-PLAN.md. Começar por auditoria dirigida e plano,
   reutilizando os componentes verificados e registrando cada lacuna.

V5, V6.3 e V6.5 são contexto histórico. A referência operacional para uma nova
sessão é AGENTS.md → PROJECT_STATE.md → ROADMAP.md → arquivos da tarefa.
Diagnóstico inicial não significa reiniciar ou reescrever código funcional.
O pedido de “100% Windows” é objetivo de desenvolvimento, não status alcançado.
