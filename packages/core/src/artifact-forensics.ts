import { sha256 } from './scanner.js';
import { ARTIFACT_LIMITS, ArtifactAnalysisError, type ArtifactAnalysisReport } from './artifact-types.js';
import { addFinding, fact, isoDate, list, record, text, type JsonObject } from './artifact-support.js';

function entropy(bytes: Uint8Array): number {
  if (!bytes.length) return 0;
  const counts = new Uint32Array(256);
  for (const value of bytes) counts[value]++;
  let value = 0;
  for (const count of counts) if (count) { const probability = count / bytes.length; value -= probability * Math.log2(probability); }
  return Math.round(value * 1000) / 1000;
}

function peMetadata(bytes: Buffer, report: ArtifactAnalysisReport): void {
  if (bytes.length < 64) throw new ArtifactAnalysisError('Cabeçalho DOS truncado.');
  const offset = bytes.readUInt32LE(0x3c);
  if (offset < 64 || offset > bytes.length - 24 || bytes.subarray(offset, offset + 4).toString('hex') !== '50450000') throw new ArtifactAnalysisError('Cabeçalho PE inválido ou ausente.');
  const sections = bytes.readUInt16LE(offset + 6);
  const optionalBytes = bytes.readUInt16LE(offset + 20);
  const optional = offset + 24;
  const table = optional + optionalBytes;
  if (sections > 96 || table > bytes.length || sections * 40 > bytes.length - table) throw new ArtifactAnalysisError('Tabela de seções PE fora dos limites.');
  const machine = bytes.readUInt16LE(offset + 4);
  fact(report, 'Formato identificado', 'PE/COFF');
  fact(report, 'Máquina PE', `0x${machine.toString(16)}`);
  fact(report, 'Seções PE', sections);
  if (optionalBytes > 0) {
    if (optionalBytes < 2) throw new ArtifactAnalysisError('Cabeçalho opcional PE truncado.');
    const magic = bytes.readUInt16LE(optional);
    if (magic !== 0x10b && magic !== 0x20b) throw new ArtifactAnalysisError('Formato de cabeçalho opcional PE não suportado.');
    fact(report, 'Formato PE', magic === 0x20b ? 'PE32+' : 'PE32');
  }
  for (let index = 0; index < sections; index++) {
    const section = table + index * 40;
    const rawSize = bytes.readUInt32LE(section + 16);
    const rawOffset = bytes.readUInt32LE(section + 20);
    const flags = bytes.readUInt32LE(section + 36);
    if (rawSize && (rawOffset < table + sections * 40 || rawOffset > bytes.length || rawSize > bytes.length - rawOffset)) throw new ArtifactAnalysisError('Dados de seção PE fora dos limites.');
    const digest = sha256(bytes.subarray(rawOffset, rawOffset + rawSize));
    if ((flags & 0x20000000) && (flags & 0x80000000)) addFinding(report, { ruleId: 'MAL-PE-WX-001', severity: 'medium', title: 'Seção PE declara escrita e execução simultâneas', location: `/binary/pe/sections/${index}`, recommendation: 'Revise a origem e a necessidade da seção com ferramentas estáticas em laboratório. A flag isolada não prova malware.', confidence: 'medium' }, { index, flags, digest });
    if (rawSize > 1024 && entropy(bytes.subarray(rawOffset, rawOffset + rawSize)) >= 7.2) addFinding(report, { ruleId: 'MAL-ENTROPY-001', severity: 'info', title: 'Seção PE possui alta entropia', location: `/binary/pe/sections/${index}`, recommendation: 'Verifique se há compressão, criptografia ou empacotamento legítimo. Alta entropia não é classificação de malware.', confidence: 'medium' }, { index, digest, entropy: entropy(bytes.subarray(rawOffset, rawOffset + rawSize)) });
  }
}

export function analyzeBinary(root: JsonObject, report: ArtifactAnalysisReport): void {
  if (root.format !== 'sentinel.binary.v1' || root.encoding !== 'base64') throw new ArtifactAnalysisError('Binário: envelope sentinel.binary.v1 com encoding base64.');
  const data = text(root.data, 'Base64', ARTIFACT_LIMITS.bytes);
  if (!data || data.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data)) throw new ArtifactAnalysisError('Base64 canônico inválido.');
  const bytes = Buffer.from(data, 'base64');
  if (bytes.toString('base64') !== data) throw new ArtifactAnalysisError('Base64 não canônico.');
  report.format = 'sentinel.binary.v1';
  fact(report, 'SHA-256 do binário decodificado', sha256(bytes)); fact(report, 'Bytes do binário', bytes.length); fact(report, 'Entropia global (bits/byte)', entropy(bytes));
  if (bytes.subarray(0, 2).toString() === 'MZ') peMetadata(bytes, report);
  else if (bytes.subarray(0, 4).toString('hex') === '7f454c46') {
    if (bytes.length < 16 || ![1, 2].includes(bytes[4]) || ![1, 2].includes(bytes[5]) || bytes[6] !== 1 || bytes.length < (bytes[4] === 2 ? 64 : 52)) throw new ArtifactAnalysisError('Cabeçalho ELF inválido ou truncado.');
    fact(report, 'Formato identificado', bytes[4] === 2 ? 'ELF64' : 'ELF32');
    fact(report, 'Máquina ELF', bytes[5] === 1 ? bytes.readUInt16LE(18) : bytes.readUInt16BE(18));
    fact(report, 'Ordem de bytes ELF', bytes[5] === 1 ? 'little-endian' : 'big-endian');
  } else if (bytes.subarray(0, 4).toString('hex') === '504b0304') fact(report, 'Assinatura inicial', 'ZIP; estrutura interna não interpretada');
  else fact(report, 'Formato identificado', 'Não identificado pelo conjunto atual');
  report.limitations.push('Triagem estática limitada de bytes, SHA-256, entropia e cabeçalhos PE/ELF. Não executa, descompacta, desofusca, consulta reputação, verifica assinatura digital nem emite veredito de malware.');
}

export function analyzeScript(content: string, report: ArtifactAnalysisReport): void {
  report.format = 'script-text';
  const lines = content.split(/\r?\n/);
  const patterns = [
    { ruleId: 'MAL-SCRIPT-ENC-001', regex: /\bpowershell(?:\.exe)?\b[^\r\n]{0,300}\s-(?:enc|encodedcommand)\s+[A-Za-z0-9+/]{16,}={0,2}/i, title: 'Invocação PowerShell com comando codificado', recommendation: 'Revise a origem e o conteúdo codificado em ferramenta estática isolada. O uso de codificação pode ser legítimo.' },
    { ruleId: 'MAL-SCRIPT-EVAL-001', regex: /\b(?:eval|Function)\s*\(\s*(?:atob\s*\(|Buffer\.from\s*\()/, title: 'Texto sugere avaliação dinâmica de conteúdo codificado', recommendation: 'Inspecione a cadeia de dados e substitua avaliação dinâmica por parsing explícito quando possível.' },
    { ruleId: 'MAL-SCRIPT-PIPE-001', regex: /\b(?:curl|wget)\b[^\r\n]{0,1000}\|\s*(?:sudo\s+)?(?:sh|bash)\b/i, title: 'Texto contém download encaminhado a interpretador', recommendation: 'Revise e fixe o conteúdo antes de permitir execução; este analisador não baixa nem executa o comando.' },
  ];
  lines.forEach((line, index) => {
    for (const pattern of patterns) if (pattern.regex.test(line)) addFinding(report, { ruleId: pattern.ruleId, severity: 'medium', title: pattern.title, location: `/text/line/${index + 1}`, recommendation: pattern.recommendation, confidence: 'medium' }, line);
  });
  fact(report, 'Linhas de texto', lines.length);
  report.limitations.push('Busca lexical de três padrões para triagem. Comentários, documentação e usos legítimos podem coincidir. Não é análise semântica, antivírus, sandbox de execução ou prova de malícia.');
}

export function analyzeTimeline(root: JsonObject, report: ArtifactAnalysisReport): void {
  if (root.format !== 'sentinel.timeline.v1') throw new ArtifactAnalysisError('Formato esperado: sentinel.timeline.v1.');
  report.format = 'sentinel.timeline.v1';
  const events = list(root.events, 'events', ARTIFACT_LIMITS.timeline);
  const seen = new Set<string>();
  let duplicates = 0;
  const timeline = events.map((raw, index) => {
    const event = record(raw, 'evento');
    const occurredAt = isoDate(event.occurredAt);
    const eventType = text(event.eventType, 'Tipo de evento', 100);
    const source = text(event.source, 'Fonte de evento', 100);
    if (!/^[a-z][a-z0-9._-]{0,99}$/i.test(eventType) || !/^[a-z][a-z0-9._-]{0,99}$/i.test(source)) throw new ArtifactAnalysisError('Tipo e fonte devem ser identificadores, sem conteúdo livre.');
    if (event.sha256 !== undefined && !/^[a-f0-9]{64}$/.test(text(event.sha256, 'SHA-256', 64))) throw new ArtifactAnalysisError('SHA-256 de referência inválido.');
    const evidenceHash = sha256(JSON.stringify(event));
    if (seen.has(evidenceHash)) duplicates++;
    seen.add(evidenceHash);
    return { occurredAt, eventType, source, evidenceHash, ordinal: index };
  });
  timeline.sort((a, b) => a.occurredAt.localeCompare(b.occurredAt) || a.ordinal - b.ordinal);
  report.timeline = timeline.map(({ ordinal: _ordinal, ...item }) => item);
  fact(report, 'Eventos no export', timeline.length); fact(report, 'Eventos idênticos repetidos', duplicates);
  if (timeline.length) { fact(report, 'Primeiro instante', timeline[0].occurredAt); fact(report, 'Último instante', timeline.at(-1)!.occurredAt); }
  report.limitations.push('Normaliza e ordena eventos exportados em UTC, preservando duplicatas. Não adquire discos ou celulares, não recupera arquivos apagados, não valida relógios de origem nem comprova autenticidade. Mensagens e caminhos não são copiados ao relatório; hashes permitem localizar o evento no original.');
}
