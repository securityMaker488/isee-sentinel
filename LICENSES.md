# Licenças e procedência

O código do Sentinel é publicado sob a GNU Affero General Public License 3
(AGPL-3.0); consulte [LICENSE](LICENSE) e o aviso de copyright no
[README](README.md). Não são copiados componentes proprietários das ferramentas de
referência, e nenhum aviso de licença de terceiro foi removido.

Inventário JavaScript gerado por `npm run inventory`: docs/generated/dependencies.json. A nova dependência saxes 6.0.0 declara ISC no pacote instalado; é um parser XML utilizado para importação delimitada com rejeição de DTD. xmlchars é dependência transitiva. Manter os avisos distribuídos pelos pacotes.

Rust: Cargo.toml e Cargo.lock fixam reqwest/rustls, HMAC/SHA256 e dependências.
Inventário do crate do agente (147 pacotes, em
[agent-dependencies.json](docs/generated/agent-dependencies.json)) e do supervisor
(23 pacotes, em
[execution-dependencies.json](docs/generated/execution-dependencies.json)) registram
licença, versão e repositório de cada dependência externa; as licenças são
predominantemente MIT/Apache-2.0, com Unicode-3.0, ISC, BSD-3-Clause, Zlib, BSL-1.0
e uma entrada dual (MIT/Apache-2.0/LGPL-2.1-or-later) que merece revisão antes
de distribuição comercial. Cargo.lock não é um parecer de licenciamento: uma
revisão completa de avisos e redistribuição continua necessária antes de
publicação comercial.

Nmap não está embutido no pacote nem foi instalado por esta alteração. O adaptador requer executável fornecido/configurado pelo operador, com licença e versão conferidas. Consulte docs/ATTACKLAB.md para as fontes oficiais verificadas do adaptador.

Demais produtos citados na matriz não foram integrados. Seus nomes identificam referências funcionais; licenças e APIs precisam ser avaliadas antes de desenvolvimento de conectores específicos.


## Supervisor, dependências e pesquisa — 02/11/2026, atualizado em 13/11/2026

`packages/execution-engine/Cargo.lock` fixa serde/serde_json/sha2 e21 pacotes
externos resolvidos no0.1.0;0.1.1 e0.2.0 mantêm23, com windows-sys0.61.2 e
windows-link0.2.1, e usam libc0.2.191 diretamente no Linux. Esses bindings já
constavam das dependências do agente. Declarações de licença/versão/repositório extraídas de cargo
metadata: [execution-dependencies.json](docs/generated/execution-dependencies.json).
Predominam MIT/Apache-2.0; unicode-ident também declara Unicode-3.0. Preservar
avisos aplicáveis na distribuição. Inventário não substitui revisão de avisos,
advisories ou permissões de redistribuição; cargo audit local não estava disponível.

O registro de pesquisa dirigida foi movido para fora do repositório na
preparação para publicação, por decisão do titular: fixava revisões e separava
licença observada de compatibilidade ainda não resolvida. Nenhum código dessas
referências foi incorporado, nem instalado como dependência ou executado, e
nenhum aviso de licença de terceiros foi removido. O supervisor usa implementação
própria de conceitos gerais de integridade/resultado de processo. Qualquer
incorporação futura requer revisar a licença efetiva antes de tratá-la como
permitida.
