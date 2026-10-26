# Segurança do Sentinel

Aplicação privada local com operador único, MFA, cookies protegidos, CSRF e isolamento por organização. Ativos vinculam projetos; acesso a operação de análise/ingestão exige escopo vigente. PostgreSQL usa papéis de migração e execução separados; atualizar grants após novas migrações.

Credenciais de agente são aleatórias, cifradas em repouso, vinculadas a ativo, expiram e podem ser revogadas. HMAC autentica corpo, método, rota, timestamp e nonce. O backend rejeita replay; a primeira coleta requer aprovação de baseline. O agente não recebe comandos. TLS é exigido pelo cliente salvo loopback explicitamente habilitado.

Analisadores operam sobre entradas limitadas sem executar artefatos. XML rejeita DTD ativo e entidades externas. Ferramentas externas recebem argumentos fixos, sem shell; o adaptador Nmap é limitado a alvo de laboratório previamente cadastrado. Nunca apontar executável de integração para diretório gravável por terceiros.

SecureFix modifica somente uma cópia cifrada. Alterações críticas no host continuam indisponíveis. A IA não pode reclassificar a própria autorização.

Chaves devem ficar fora de backups do banco e ter cópia protegida separada. A perda da chave pode tornar evidências irrecuperáveis. Hash e trigger append-only não garantem resistência contra administrador do banco. Consulte docs/AMEACAS-E-SEGURANCA.md e BACKUP_RECOVERY.md.

Limitações: homologação Debian pendente; retenção automatizada, assinatura de distribuição, revisão independente e isolamento de workers ainda incompletos. Não expor a interface administrativa publicamente por padrão.
