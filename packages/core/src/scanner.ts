import { createHash } from 'node:crypto';
import type { ControlCheck, Finding, ScanResult, Severity, UploadedFile } from './types.js';

export const SCAN_LIMITS = Object.freeze({ maxFiles: 40, maxFileBytes: 256 * 1024, maxTotalBytes: 1024 * 1024, maxPathLength: 240 });
export const RULE_SET_VERSION = '1.0.0';
export interface DetectionRule {
  id: string;
  version: string;
  title: string;
  severity: Severity;
  recommendation: string;
  layerId: string;
  controlId: string;
}
export const RULES: readonly DetectionRule[] = Object.freeze([
  { id: 'SB-TLS-001', version: '1.0.0', title: 'Verificação de certificado TLS desabilitada', severity: 'high', recommendation: 'Habilite a validação de certificados e configure uma autoridade certificadora confiável.', layerId: 'cryptography', controlId: 'tls.verification' },
  { id: 'SB-SSH-001', version: '1.0.0', title: 'Login SSH direto de root permitido', severity: 'high', recommendation: 'Defina PermitRootLogin no e valide a configuração efetiva em ambiente autorizado antes de reiniciar o SSH.', layerId: 'endpoint', controlId: 'ssh.root_login' },
  { id: 'SB-SSH-002', version: '1.0.0', title: 'Autenticação SSH por senha permitida', severity: 'medium', recommendation: 'Migre para chaves ou autenticação forte e defina PasswordAuthentication no após validar um acesso alternativo.', layerId: 'endpoint', controlId: 'ssh.password_authentication' },
  { id: 'SB-CORS-001', version: '1.0.0', title: 'CORS combina origem curinga e credenciais', severity: 'medium', recommendation: 'Use uma lista explícita de origens autorizadas. Verifique a resposta HTTP efetiva; navegadores bloqueiam a combinação curinga e credenciais.', layerId: 'application', controlId: 'cors.origin_credentials' },
  { id: 'SB-SECRET-001', version: '1.0.0', title: 'Marcador de chave privada no conteúdo enviado', severity: 'critical', recommendation: 'Remova o material privado do projeto, investigue exposição e revogue ou rotacione a chave se ela for válida.', layerId: 'cryptography', controlId: 'secrets.private_key' },
  { id: 'SB-SECRET-002', version: '1.0.0', title: 'Possível credencial AWS no conteúdo enviado', severity: 'high', recommendation: 'Confirme a credencial em canal seguro, revogue ou rotacione se válida e utilize credenciais temporárias fora do código.', layerId: 'cryptography', controlId: 'secrets.cloud_key' },
]);

export class ScanValidationError extends Error {
  readonly code = 'INVALID_SCAN_INPUT';
  constructor(message: string) { super(message); this.name = 'ScanValidationError'; }
}

export const sha256 = (content: string | Uint8Array): string => createHash('sha256').update(content).digest('hex');

/** Uploads are text values only: this function never opens paths, follows links, executes code, or accesses a network. */
export function validateUploadedFiles(input: unknown): UploadedFile[] {
  if (!Array.isArray(input) || input.length === 0 || input.length > SCAN_LIMITS.maxFiles) {
    throw new ScanValidationError(`Envie de 1 a ${SCAN_LIMITS.maxFiles} arquivos de texto.`);
  }
  const seen = new Set<string>();
  let total = 0;
  return input.map(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item) || typeof item.path !== 'string' || typeof item.content !== 'string'
      || Object.keys(item).some(key => key !== 'path' && key !== 'content')) {
      throw new ScanValidationError('Cada arquivo deve conter somente path e content textuais; metadados de links não são aceitos.');
    }
    const path = item.path as string;
    // Reject POSIX roots, drives, UNC, URI schemes, alternate streams, encoded traversal, controls and ambiguous segments.
    if (path.length === 0 || path.length > SCAN_LIMITS.maxPathLength || /^[\\/]/.test(path)
      || /[\x00-\x1f\x7f:%<>"|?*]/.test(path) || path.includes('\\')
      || path.split('/').some(segment => !segment || segment === '.' || segment === '..' || /[. ]$/.test(segment))) {
      throw new ScanValidationError('Caminho inválido: use um caminho relativo POSIX sem segmentos ambíguos.');
    }
    const normalized = path.toLocaleLowerCase('en-US');
    if (seen.has(normalized)) throw new ScanValidationError('Caminhos duplicados não são permitidos.');
    seen.add(normalized);
    const bytes = Buffer.byteLength(item.content, 'utf8');
    total += bytes;
    if (bytes > SCAN_LIMITS.maxFileBytes || total > SCAN_LIMITS.maxTotalBytes) {
      throw new ScanValidationError('Limite de tamanho de arquivos excedido.');
    }
    if (item.content.includes('\0')) throw new ScanValidationError('Conteúdo binário com NUL não é aceito.');
    return { path, content: item.content };
  });
}

type Reporter = (ruleId: string, line: number, failed: boolean, explanation: string, confidence?: 'high' | 'medium') => void;

function parseEnv(content: string): Map<string, { value: string; line: number }> {
  const result = new Map<string, { value: string; line: number }>();
  content.split(/\r?\n/).forEach((line, index) => {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match) return;
    let value = match[2];
    if (/^["']/.test(value)) {
      const quoted = value.match(/^(["'])(.*?)\1\s*(?:#.*)?$/);
      if (!quoted) return;
      value = quoted[2];
    } else value = value.replace(/\s+#.*$/, '').trim();
    result.set(match[1], { value, line: index + 1 });
  });
  return result;
}

function scanEnv(content: string, report: Reporter): void {
  const env = parseEnv(content);
  const tls = env.get('NODE_TLS_REJECT_UNAUTHORIZED');
  if (tls && ['0', '1'].includes(tls.value)) report('SB-TLS-001', tls.line, tls.value === '0', 'Valor explícito da variável NODE_TLS_REJECT_UNAUTHORIZED no arquivo enviado.');
  const origin = env.get('CORS_ORIGIN');
  const credentials = env.get('CORS_CREDENTIALS');
  if (origin && credentials && ['true', 'false'].includes(credentials.value.toLowerCase())) {
    report('SB-CORS-001', origin.line, origin.value === '*' && credentials.value.toLowerCase() === 'true', 'Par CORS_ORIGIN/CORS_CREDENTIALS declarado no mesmo arquivo; a aplicação deve confirmar que usa estas variáveis.', 'medium');
  }
}

function scanSsh(content: string, report: Reporter, limitations: Set<string>): void {
  const records: { directive: string; value: string; line: number; context: number }[] = [];
  let context = 0;
  let includes = false;
  let duplicates = false;
  const seen = new Set<string>();
  content.split(/\r?\n/).forEach((line, index) => {
    const match = line.match(/^\s*([A-Za-z]+)(?:\s+|\s*=\s*)([^#]*?)(?:\s+#.*)?\s*$/);
    if (!match) return;
    const directive = match[1].toLowerCase();
    if (directive === 'match') { context++; return; }
    if (directive === 'include') { includes = true; return; }
    if (!['permitrootlogin', 'passwordauthentication'].includes(directive)) return;
    const key = `${context}:${directive}`;
    if (seen.has(key)) { duplicates = true; return; } // sshd uses the first value within a configuration context.
    seen.add(key);
    records.push({ directive, value: match[2].trim().toLowerCase(), line: index + 1, context });
  });
  if (includes) limitations.add('Diretivas SSH Include não são resolvidas. Não há aprovação de controles SSH quando Includes podem alterar o resultado.');
  if (context || duplicates) limitations.add('Configuração SSH contém Match ou diretivas duplicadas; não são emitidos resultados pass para estes arquivos.');
  for (const [directive, ruleId] of [['permitrootlogin', 'SB-SSH-001'], ['passwordauthentication', 'SB-SSH-002']]) {
    const values = records.filter(record => record.directive === directive);
    const insecure = values.filter(record => record.value === 'yes');
    if (insecure.length) {
      for (const item of insecure) report(ruleId, item.line, true, item.context === 0 ? 'Diretiva explícita no bloco global do arquivo SSH enviado.' : 'Diretiva explícita em bloco Match; o alcance depende das condições do bloco.', includes || item.context > 0 ? 'medium' : 'high');
    } else {
      const global = values.find(record => record.context === 0);
      if (!includes && !context && !duplicates && global?.value === 'no' && values.every(record => record.value === 'no')) {
        report(ruleId, global.line, false, 'Diretiva explicitamente desabilitada no arquivo enviado, sem Include. Não confirma a configuração carregada pelo serviço.');
      }
    }
  }
}

function scanJson(content: string, report: Reporter, limitations: Set<string>): void {
  try { JSON.parse(content); } catch { limitations.add('Ao menos um arquivo JSON inválido não teve suas configurações avaliadas.'); return; }
  // Tokenize already validated JSON to retain exact source lines and pair options within their own object.
  interface Context { kind: 'object' | 'array'; properties: Map<string, { value: unknown; line: number }>; key?: { value: string; line: number }; expectsKey: boolean; evaluate: boolean }
  const stack: Context[] = [];
  const tokens = /"(?:\\[\s\S]|[^"\\])*"|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\]:,]/g;
  let objects = 0;
  let line = 1;
  let previous = 0;
  for (const match of content.matchAll(tokens)) {
    line += content.slice(previous, match.index).split('\n').length - 1;
    previous = match.index + match[0].length;
    const token = match[0];
    const current = stack.at(-1);
    if (token === '{' || token === '[') {
      if (current?.key) { current.properties.set(current.key.value, { value: undefined, line: current.key.line }); current.key = undefined; }
      const evaluate = stack.length < 64 && ++objects <= 10000;
      if (!evaluate) limitations.add('Limite estrutural JSON atingido; objetos além de 64 níveis ou 10.000 objetos não foram avaliados.');
      stack.push({ kind: token === '{' ? 'object' : 'array', properties: new Map(), expectsKey: true, evaluate });
    } else if (token === '}' || token === ']') {
      const closed = stack.pop()!;
      if (closed.kind !== 'object' || !closed.evaluate) continue;
      const tls = closed.properties.get('rejectUnauthorized');
      const origin = closed.properties.get('origin');
      const credentials = closed.properties.get('credentials');
      if (tls && typeof tls.value === 'boolean') report('SB-TLS-001', tls.line, !tls.value, 'Propriedade booleana rejectUnauthorized em objeto JSON válido.');
      if (origin && credentials && typeof origin.value === 'string' && typeof credentials.value === 'boolean') {
        report('SB-CORS-001', origin.line, origin.value === '*' && credentials.value, 'Propriedades origin e credentials no mesmo objeto JSON.');
      }
    } else if (current?.kind === 'object') {
      if (token === ',') { current.expectsKey = true; current.key = undefined; }
      else if (token === ':') current.expectsKey = false;
      else if (current.expectsKey && token.startsWith('"')) current.key = { value: JSON.parse(token) as string, line };
      else if (current.key) { current.properties.set(current.key.value, { value: JSON.parse(token) as unknown, line: current.key.line }); current.key = undefined; }
    }
  }
}

function scanSecrets(content: string, report: Reporter): void {
  content.split(/\r?\n/).forEach((line, index) => {
    if (/-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/.test(line)) {
      report('SB-SECRET-001', index + 1, true, 'Marcador de material privado detectado; conteúdo sempre omitido.', 'medium');
    }
    if (/(?:^|[^A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?:[^A-Z0-9]|$)/.test(line)
      || /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}(?:["'\s,;]|$)/.test(line)) {
      report('SB-SECRET-002', index + 1, true, 'Padrão de credencial AWS detectado; conteúdo sempre omitido. Validade não foi consultada.', 'medium');
    }
  });
}

export function scanFiles(input: readonly UploadedFile[] | unknown): ScanResult {
  const files = validateUploadedFiles(input);
  const findings: Finding[] = [];
  const checks: ControlCheck[] = [];
  const limitations = new Set([
    'Baseline estático de arquivos de texto enviados. Não é SAST completo, DAST, análise de dependências ou teste de exploração.',
    'Não executa arquivos, não lê caminhos do host e não acessa URLs. Apenas .env, JSON e configuração sshd recebem verificações específicas; padrões de segredos abrangem todos os textos.',
    'Resultados descrevem o artefato enviado; não demonstram implantação, eficácia em execução, ausência de vulnerabilidades ou integridade de autoria.',
    'Achados omitem todo trecho de conteúdo. Detectores de segredos usam padrões limitados e exigem confirmação segura.',
  ]);
  const evidence = files.map(file => ({ path: file.path, sha256: sha256(file.content), bytes: Buffer.byteLength(file.content, 'utf8') }));
  for (let index = 0; index < files.length; index++) {
    const file = files[index];
    const evidenceHash = evidence[index].sha256;
    const report: Reporter = (ruleId, line, failed, explanation, confidence = 'high') => {
      const rule = RULES.find(candidate => candidate.id === ruleId)!;
      checks.push({ controlId: rule.controlId, layerId: rule.layerId, status: failed ? 'fail' : 'pass', path: file.path, line, evidenceHash, explanation, assurance: 'static_configuration' });
      if (!failed) return;
      const id = sha256(`${RULE_SET_VERSION}\0${file.path}\0${evidenceHash}\0${rule.id}\0${line}`).slice(0, 32);
      if (findings.some(finding => finding.id === id)) return;
      findings.push({ id, ruleId: rule.id, ruleVersion: rule.version, severity: rule.severity, path: file.path, line,
        title: rule.title, recommendation: rule.recommendation, confidence, evidenceHash, layerId: rule.layerId });
    };
    const basename = file.path.split('/').at(-1)!;
    if (basename === '.env' || basename.startsWith('.env.')) scanEnv(file.content, report);
    if (basename === 'sshd_config' || /(?:^|\/)sshd_config\.d\/[^/]+\.conf$/.test(file.path)) scanSsh(file.content, report, limitations);
    if (file.path.toLowerCase().endsWith('.json')) scanJson(file.content, report, limitations);
    scanSecrets(file.content, report);
  }
  evidence.sort((a, b) => a.path.localeCompare(b.path, 'en'));
  return { schemaVersion: '1.0', engine: 'SecureBuild Static Baseline', ruleSetVersion: RULE_SET_VERSION,
    inputHash: sha256(JSON.stringify(evidence)), files: evidence, findings, checks, limitations: [...limitations] };
}
