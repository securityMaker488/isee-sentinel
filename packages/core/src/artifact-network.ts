import { SaxesParser } from 'saxes';
import { ARTIFACT_LIMITS, ArtifactAnalysisError, type ArtifactAnalysisReport } from './artifact-types.js';
import { addFinding, fact, list, record, text, type JsonObject } from './artifact-support.js';

export function analyzeNmap(content: string, report: ArtifactAnalysisReport): void {
  report.format = 'nmap-xml';
  const parser = new SaxesParser({ xmlns: false });
  const path: string[] = [];
  let nodes = 0; let hosts = 0; let ports = 0; let open = 0; let up = 0;
  let hostUp = false;
  let port: { protocol: string; number: number; state?: string; service?: string; method?: string; confidence?: number } | undefined;
  let root = false;
  parser.on('doctype', value => {
    // Nmap emits this inert root declaration. External and internal subsets remain forbidden.
    if (value.trim() !== 'nmaprun') throw new ArtifactAnalysisError('DTD externo, subconjuntos e declarações de entidades não são aceitos.');
  });
  parser.on('processinginstruction', () => { /* Stylesheets and processing instructions are never fetched or evaluated. */ });
  parser.on('opentag', node => {
    if (++nodes > ARTIFACT_LIMITS.nodes || path.length >= ARTIFACT_LIMITS.depth) throw new ArtifactAnalysisError('Limite estrutural XML excedido.');
    path.push(node.name);
    const here = path.join('/');
    if (path.length === 1) {
      if (node.name !== 'nmaprun' || node.attributes.scanner !== 'nmap') throw new ArtifactAnalysisError('XML deve ser uma saída Nmap com scanner="nmap".');
      root = true;
    }
    if (here === 'nmaprun/host') {
      if (++hosts > ARTIFACT_LIMITS.records) throw new ArtifactAnalysisError('Muitos hosts no XML.');
      hostUp = false;
    }
    if (here === 'nmaprun/host/status') { hostUp = node.attributes.state === 'up'; if (hostUp) up++; }
    if (here === 'nmaprun/host/ports/port') {
      if (++ports > ARTIFACT_LIMITS.records) throw new ArtifactAnalysisError('Muitas portas no XML.');
      const number = Number(node.attributes.portid);
      const protocol = node.attributes.protocol;
      if (typeof protocol !== 'string' || !['tcp', 'udp', 'sctp'].includes(protocol) || !/^\d{1,5}$/.test(String(node.attributes.portid)) || !Number.isInteger(number) || number < 0 || number > 65535) throw new ArtifactAnalysisError('Porta Nmap inválida.');
      port = { protocol, number };
    }
    if (here === 'nmaprun/host/ports/port/state' && port) port.state = String(node.attributes.state);
    if (here === 'nmaprun/host/ports/port/service' && port) {
      port.service = typeof node.attributes.name === 'string' ? node.attributes.name.slice(0, 100) : undefined;
      port.method = typeof node.attributes.method === 'string' ? node.attributes.method : undefined;
      port.confidence = Number(node.attributes.conf);
    }
  });
  parser.on('closetag', () => {
    if (path.join('/') === 'nmaprun/host/ports/port' && port) {
      if (!port.state || !['open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered'].includes(port.state)) throw new ArtifactAnalysisError('Estado de porta ausente ou inválido.');
      if (port.state === 'open') {
        open++;
        const location = `/nmaprun/host[${hosts}]/ports/port[${port.number}/${port.protocol}]`;
        addFinding(report, { ruleId: 'NET-OPEN-001', severity: 'info', title: `Porta ${port.number}/${port.protocol} aberta no relatório importado`, location, recommendation: 'Confirme o responsável e a necessidade de exposição desta porta dentro do escopo autorizado.', confidence: 'medium', provenance: 'imported_tool' }, { hostIndex: hosts, hostUp, ...port });
        if (port.method === 'probed' && Number.isFinite(port.confidence) && port.confidence! >= 7 && ['telnet', 'ftp', 'pop3', 'imap'].includes(port.service ?? '')) {
          addFinding(report, { ruleId: 'NET-PLAINTEXT-001', severity: 'medium', title: 'Scanner identificou serviço com variante de protocolo sem TLS', location, recommendation: 'Confirme se TLS/STARTTLS é exigido e se autenticação em texto claro é bloqueada; o nome do serviço não comprova exposição de credenciais.', confidence: 'medium', provenance: 'imported_tool' }, { hostIndex: hosts, ...port });
        }
      }
      port = undefined;
    }
    path.pop();
  });
  try { parser.write(content).close(); } catch (error) {
    if (error instanceof ArtifactAnalysisError) throw error;
    throw new ArtifactAnalysisError('XML Nmap inválido ou entidade não permitida.');
  }
  if (!root) throw new ArtifactAnalysisError('XML Nmap vazio.');
  fact(report, 'Hosts no relatório', hosts); fact(report, 'Hosts declarados ativos', up); fact(report, 'Portas detalhadas', ports); fact(report, 'Portas declaradas abertas', open);
  report.limitations.push('Importação passiva do XML: não executa Nmap, scripts NSE, comandos, XSL ou consultas DNS. Não confirma o alvo, a data, a autenticidade ou o estado atual. Porta aberta não implica vulnerabilidade; scripts e extraports não são interpretados.');
}

function headers(raw: unknown): Map<string, string[]> {
  const result = new Map<string, string[]>();
  for (const item of list(raw, 'headers', 2000)) {
    const header = record(item, 'header');
    const name = text(header.name, 'Nome do header', 256).toLowerCase();
    const value = text(header.value, 'Valor do header', 65536);
    const values = result.get(name) ?? [];
    values.push(value); result.set(name, values);
  }
  return result;
}

export function analyzeHar(root: JsonObject, report: ArtifactAnalysisReport): void {
  const log = record(root.log, 'log HAR');
  if (log.version !== '1.2') throw new ArtifactAnalysisError('HAR suportado: versão 1.2.');
  report.format = 'har-1.2';
  const entries = list(log.entries, 'entries');
  let encrypted = 0; let plaintext = 0; let cookies = 0;
  const origins = new Set<string>();
  entries.forEach((raw, index) => {
    const entry = record(raw, 'entrada HAR');
    const request = record(entry.request, 'request');
    const response = record(entry.response, 'response');
    text(request.method, 'Método', 30);
    let url: URL;
    try { url = new URL(text(request.url, 'URL', 16384)); } catch { throw new ArtifactAnalysisError('URL HAR inválida.'); }
    if (!['http:', 'https:'].includes(url.protocol)) throw new ArtifactAnalysisError('HAR deve conter URLs HTTP ou HTTPS.');
    origins.add(url.origin);
    if (url.protocol === 'https:') encrypted++; else plaintext++;
    const location = `/log/entries/${index}`;
    const reqHeaders = headers(request.headers);
    const resHeaders = headers(response.headers);
    const requestCookies = list(request.cookies ?? [], 'cookies');
    const credentials = reqHeaders.has('authorization') || reqHeaders.has('proxy-authorization') || reqHeaders.has('cookie') || requestCookies.length > 0 || Boolean(url.username || url.password);
    if (url.protocol === 'http:') addFinding(report, { ruleId: 'NET-HTTP-001', severity: credentials ? 'high' : 'medium', title: credentials ? 'Requisição HTTP sem TLS com credenciais no export' : 'Requisição HTTP sem TLS no export', location, recommendation: 'Use HTTPS e verifique redirecionamento seguro antes de transmitir conteúdo sensível. As credenciais e a URL não são copiadas para o relatório.' }, { url: request.url, headers: request.headers });
    if (credentials) addFinding(report, { ruleId: 'NET-HAR-SECRET-001', severity: 'info', title: 'HAR contém dados de autenticação potencialmente sensíveis', location, recommendation: 'Mantenha o original cifrado, compartilhe uma cópia redigida e rotacione credenciais que tenham sido expostas.' }, { headers: request.headers, cookies: request.cookies, credentialsInUrl: Boolean(url.username || url.password) });
    const sensitiveQuery = [...url.searchParams.keys()].some(name => /^(?:access_token|token|api[_-]?key|password|secret|authorization)$/i.test(name));
    if (sensitiveQuery) addFinding(report, { ruleId: 'NET-QUERY-001', severity: 'medium', title: 'Parâmetro de URL com nome associado a segredo', location, recommendation: 'Evite credenciais em URLs, que podem persistir em históricos e logs. Revise e rotacione o valor se for válido.', confidence: 'medium' }, request.url);
    if ((resHeaders.get('access-control-allow-origin') ?? []).some(value => value.trim() === '*') && (resHeaders.get('access-control-allow-credentials') ?? []).some(value => value.trim().toLowerCase() === 'true')) addFinding(report, { ruleId: 'NET-CORS-001', severity: 'medium', title: 'Resposta combina CORS curinga e credenciais', location, recommendation: 'Configure uma origem explícita permitida; navegadores rejeitam credenciais nessa combinação.' }, { headers: response.headers });
    (resHeaders.get('set-cookie') ?? []).forEach((value, cookieIndex) => {
      cookies++;
      const parts = value.split(';').slice(1).map(part => part.trim().split('=', 1)[0].toLowerCase());
      if (url.protocol === 'https:' && !parts.includes('secure')) addFinding(report, { ruleId: 'NET-COOKIE-001', severity: 'medium', title: 'Cookie emitido via HTTPS sem atributo Secure', location: `${location}/response/set-cookie/${cookieIndex}`, recommendation: 'Aplique Secure aos cookies que devam circular somente sob TLS. Revise sua finalidade antes de alterar atributos.' }, value);
    });
  });
  fact(report, 'Requisições', entries.length); fact(report, 'Requisições HTTPS', encrypted); fact(report, 'Requisições HTTP', plaintext); fact(report, 'Origens distintas', origins.size); fact(report, 'Headers Set-Cookie', cookies);
  report.limitations.push('Analisa somente as entradas HAR enviadas. Não reproduz requisições, não captura tráfego, não lê corpos em busca de dados pessoais e não demonstra exploração. URLs, cabeçalhos e valores de cookies ficam omitidos dos achados.');
}

export function importSarif(root: JsonObject, report: ArtifactAnalysisReport): void {
  if (root.version !== '2.1.0') throw new ArtifactAnalysisError('SARIF suportado: 2.1.0.');
  report.format = 'sarif-2.1.0';
  const runs = list(root.runs, 'runs', 50);
  let results = 0; let omitted = 0;
  runs.forEach((rawRun, runIndex) => {
    const run = record(rawRun, 'run');
    const driver = record(record(run.tool, 'tool').driver, 'driver');
    text(driver.name, 'Nome do analisador', 256);
    const rules = driver.rules === undefined ? [] : list(driver.rules, 'rules');
    list(run.results ?? [], 'results').forEach((rawResult, resultIndex) => {
      if (++results > ARTIFACT_LIMITS.records) throw new ArtifactAnalysisError('Muitos resultados SARIF.');
      const result = record(rawResult, 'resultado');
      record(result.message, 'message');
      const kind = result.kind ?? 'fail';
      if (!['notApplicable', 'pass', 'fail', 'review', 'open', 'informational'].includes(String(kind))) throw new ArtifactAnalysisError('kind SARIF inválido.');
      const suppressed = result.suppressions !== undefined && list(result.suppressions, 'suppressions').some(item => record(item).status === 'accepted');
      if (suppressed || kind === 'pass' || kind === 'notApplicable') { omitted++; return; }
      let descriptor: JsonObject | undefined;
      if (result.ruleIndex !== undefined) {
        if (!Number.isInteger(result.ruleIndex) || Number(result.ruleIndex) < 0 || Number(result.ruleIndex) >= rules.length) throw new ArtifactAnalysisError('ruleIndex SARIF inválido.');
        descriptor = record(rules[Number(result.ruleIndex)], 'regra');
      } else if (typeof result.ruleId === 'string') descriptor = rules.map(item => record(item)).find(item => item.id === result.ruleId);
      const defaultLevel = descriptor?.defaultConfiguration === undefined ? undefined : record(descriptor.defaultConfiguration).level;
      const level = result.level ?? defaultLevel ?? (kind === 'fail' ? 'warning' : 'none');
      if (!['none', 'note', 'warning', 'error'].includes(String(level))) throw new ArtifactAnalysisError('level SARIF inválido.');
      const severity = kind !== 'fail' ? 'info' : level === 'error' ? 'high' : level === 'warning' ? 'medium' : 'info';
      addFinding(report, { ruleId: 'IMPORT-SARIF-001', severity, title: kind === 'fail' ? 'Falha informada por ferramenta no SARIF importado' : 'Resultado informativo ou pendente no SARIF importado', location: `/runs/${runIndex}/results/${resultIndex}`, recommendation: 'Revise a regra e a localização no original cifrado, confirme o contexto e reproduza o resultado em escopo autorizado.', confidence: 'medium', provenance: 'imported_tool' }, result);
    });
  });
  fact(report, 'Execuções importadas', runs.length); fact(report, 'Resultados de origem', results); fact(report, 'Resultados aprovados, não aplicáveis ou suprimidos omitidos', omitted);
  report.limitations.push('Importação de resultados de terceiros sem reexecutar ferramentas. A severidade SARIF error/warning/note é normalizada para high/medium/info, não é CVSS. Não resolve referências externas, não aplica fixes e não copia mensagens, snippets ou URLs que possam conter segredos.');
}
