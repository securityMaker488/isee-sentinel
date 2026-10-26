# Licenças e procedência

O código original do Sentinel permanece proprietário; consulte LICENSE. Não são copiados componentes proprietários das ferramentas de referência.

Inventário JavaScript gerado por `npm run inventory`: docs/generated/dependencies.json. A nova dependência saxes 6.0.0 declara ISC no pacote instalado; é um parser XML utilizado para importação delimitada com rejeição de DTD. xmlchars é dependência transitiva. Manter os avisos distribuídos pelos pacotes.

Rust: Cargo.toml e Cargo.lock fixam reqwest/rustls, HMAC/SHA256 e dependências. Cargo.lock não é um parecer de licenciamento: uma revisão completa de avisos e redistribuição continua necessária antes de publicação comercial.

Nmap não está embutido no pacote nem foi instalado por esta alteração. O adaptador requer executável fornecido/configurado pelo operador, com licença e versão conferidas. Consulte docs/ATTACKLAB.md para as fontes oficiais verificadas do adaptador.

Demais produtos citados na matriz não foram integrados. Seus nomes identificam referências funcionais; licenças e APIs precisam ser avaliadas antes de desenvolvimento de conectores específicos.
