# Laboratórios e limites

Classe A: arquivos benignos, fixtures sintéticas, parsers offline e desenvolvimento local.
Classe B: alvos vulneráveis e simulações autorizadas em VM/rede isolada, com autorização e caminho de retorno.
Classe C: amostras não confiáveis; exige infraestrutura específica validada, controle de saída, snapshots e avaliação de escape. Não está habilitada nesta entrega.

Nmap recebe apenas um alvo IPv4 de laboratório cadastrado e até 16 portas. Endereço privado não comprova isolamento: a rede e a posse/autorização do alvo precisam ser verificadas pelo operador. O adaptador não oferece exploração, scripts NSE, shell arbitrário ou escalada.

Nenhum malware real será executado no host. Podman rootless é opcional e não substitui VM. Kali/QEMU/KVM não foram instalados ou iniciados nesta sessão. Consulte docs/FASES-V6.5.md para o diagnóstico de hardware e os critérios de implantação ainda aplicáveis.
