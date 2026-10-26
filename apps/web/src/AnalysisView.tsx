import { useEffect, useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import type { AnalysisKind, ArtifactAnalysisReport } from '@sentinel/core';
import { date, message, request, type Asset, type Session } from './api';

interface Props { session: Session; assets: Asset[]; onChanged: () => void }
interface AnalysisRow { id: string; assetId: string; kind: AnalysisKind; evidenceId: string; createdAt?: string; summary: string; findingCount: number }
interface AnalysisDetail { id: string; assetId: string; kind: AnalysisKind; evidenceId: string; createdAt?: string; report: ArtifactAnalysisReport }
const choices: { value: AnalysisKind; label: string; description: string; format: string; example?: unknown }[] = [
  { value: 'api', label: 'API Security / OpenAPI', description: 'Auditoria passiva de autenticação declarada, esquemas, servidores e limites. Não faz requisições à API nem comprova autorização em execução.', format: 'OpenAPI 3.0.x ou 3.1.x JSON' },
  { value: 'dependency', label: 'Dependências / SecureBuild', description: 'Inventário e higiene de dependências: integridade declarada, scripts de instalação e origem dos pacotes.', format: 'package-lock.json v2/v3, CycloneDX JSON 1.4–1.6 ou SARIF 2.1.0' },
  { value: 'network', label: 'Rede / Nmap e HAR', description: 'Importa portas e serviços descritos pelo Nmap ou examina transporte, cookies e exposição de credenciais em HAR.', format: 'XML Nmap, HAR 1.2 JSON ou SARIF 2.1.0' },
  { value: 'malware', label: 'MalwareLens / Triagem estática', description: 'Metadados, hashes e cabeçalhos PE/ELF de arquivos binários; padrões limitados em scripts de texto. O conteúdo é apenas lido.', format: 'Arquivo binário, script de texto ou envelope sentinel.binary.v1' },
  { value: 'identity', label: 'IdentityGuard / Identidades', description: 'Identifica contas ativas sem MFA e contas sem login há mais de 90 dias no export enviado.', format: 'JSON sentinel.identity.v1', example: { format: 'sentinel.identity.v1', observedAt: '2026-10-24T00:00:00Z', accounts: [{ id: 'identificador-da-conta', enabled: true, privileged: false, mfaEnabled: true, lastLoginAt: '2026-10-23T00:00:00Z' }] } },
  { value: 'cloud', label: 'CloudShield / Configuração cloud', description: 'Revisa declarações IAM amplas e controles de bloqueio público S3 a partir de arquivos exportados.', format: 'Política IAM JSON, PublicAccessBlockConfiguration S3 ou sentinel.cloud.v1', example: { Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::meu-bucket/*' }] } },
  { value: 'ai', label: 'AI Security / Configuração de IA', description: 'Revisa aprovação de ações, destinos de rede, retenção de prompts e referências a credenciais.', format: 'JSON sentinel.ai.v1', example: { format: 'sentinel.ai.v1', tools: [{ name: 'consulta', enabled: true, requiresApproval: true, capabilities: ['read', 'network'], allowedHosts: ['api.example.test'] }], dataRetention: { storesPrompts: false, redactionEnabled: true }, credentials: { apiKey: 'env:API_KEY' } } },
  { value: 'forensic', label: 'DeepTrace / Linha do tempo', description: 'Ordena eventos exportados em UTC e preserva hashes para localizar cada registro na evidência original.', format: 'JSON sentinel.timeline.v1', example: { format: 'sentinel.timeline.v1', events: [{ occurredAt: '2026-10-24T00:00:00Z', eventType: 'file.write', source: 'coleta-autorizada', message: 'Descrição opcional; fica somente no original cifrado.' }] } },
];
const severity: Record<string, string> = { critical: 'Crítica', high: 'Alta', medium: 'Média', low: 'Baixa', info: 'Informativa' };
const maxBytes = 1024 * 1024;

export default function AnalysisView({ session, assets, onChanged }: Props) {
  const [rows, setRows] = useState<AnalysisRow[]>([]);
  const [detail, setDetail] = useState<AnalysisDetail | null>(null);
  const [kind, setKind] = useState<AnalysisKind>('dependency');
  const [assetId, setAssetId] = useState('');
  const [name, setName] = useState('');
  const [mediaType, setMediaType] = useState('application/json');
  const [content, setContent] = useState('');
  const [binary, setBinary] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const alive = useRef(true), generation = useRef(0), uploadGeneration = useRef(0);
  const choice = choices.find(item => item.value === kind)!;
  const canCreate = session.user.role === 'admin' || session.user.role === 'analyst';
  const byteCount = new TextEncoder().encode(content).byteLength;

  async function load() {
    const result = await request<{ items: AnalysisRow[] }>('/analyses');
    if (alive.current) setRows(result.items);
  }
  useEffect(() => {
    alive.current = true;
    void load().catch(err => { if (alive.current) setError(message(err)); }).finally(() => { if (alive.current) setLoading(false); });
    return () => { alive.current = false; ++generation.current; ++uploadGeneration.current; };
  }, []);

  function changeKind(value: AnalysisKind) {
    ++uploadGeneration.current;
    setKind(value); setBinary(false); setContent(''); setName(''); setMediaType('application/json'); setError('');
  }
  async function upload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    const current = ++uploadGeneration.current;
    setError(''); setNotice('');
    try {
      if (file.size === 0 || file.size > maxBytes) throw new Error('Escolha um arquivo não vazio de até 1 MiB.');
      let body: string;
      let mime: string;
      if (kind === 'malware' && binary) {
        // Base64 is transported as inert JSON; no object URL or executable context is created.
        const bytes = new Uint8Array(await file.arrayBuffer());
        let raw = '';
        for (let offset = 0; offset < bytes.length; offset += 32768) raw += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
        body = JSON.stringify({ format: 'sentinel.binary.v1', encoding: 'base64', data: btoa(raw) });
        mime = 'application/vnd.sentinel.binary+json';
      } else {
        body = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
        mime = body.trimStart().startsWith('<') && kind === 'network' ? 'application/xml' : body.trimStart().startsWith('{') && !(kind === 'malware' && /\.(?:js|ps1|sh|py|txt)$/i.test(file.name)) ? 'application/json' : 'text/plain';
      }
      if (new TextEncoder().encode(body).byteLength > maxBytes) throw new Error('O envelope de envio excede 1 MiB. Para binários, use um arquivo menor que 768 KiB.');
      if (body.includes('\0')) throw new Error('Conteúdo binário detectado. Em MalwareLens, marque a opção de arquivo binário antes de selecionar o arquivo.');
      if (!alive.current || current !== uploadGeneration.current) return;
      setContent(body); setMediaType(mime); setName(file.name.slice(0, 240));
      setNotice('Arquivo carregado para revisão. A análise começa ao enviar o formulário.');
    } catch (err) { if (alive.current && current === uploadGeneration.current) setError(message(err)); }
  }
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!content || byteCount > maxBytes) { setError('O artefato deve ter de 1 byte a 1 MiB.'); return; }
    ++generation.current; ++uploadGeneration.current;
    setBusy(true); setError(''); setNotice('');
    try {
      const result = await request<AnalysisDetail>('/analyses', { method: 'POST', csrfToken: session.csrfToken, body: { assetId, kind, name, mediaType, content } });
      if (!alive.current) return;
      setDetail(result); setContent(''); setName('');
      setNotice('Análise registrada. O original foi preservado como evidência cifrada.');
      await load(); if (alive.current) onChanged();
    } catch (err) { if (alive.current) setError(message(err)); }
    finally { if (alive.current) setBusy(false); }
  }
  async function inspect(id: string) {
    const current = ++generation.current;
    setDetail(null); setError(''); setLoading(true);
    try { const result = await request<AnalysisDetail>(`/analyses/${encodeURIComponent(id)}`); if (alive.current && current === generation.current) setDetail(result); }
    catch (err) { if (alive.current && current === generation.current) setError(message(err)); }
    finally { if (alive.current && current === generation.current) setLoading(false); }
  }
  async function download() {
    if (!detail) return;
    const id = detail.id;
    setBusy(true); setError('');
    try {
      const result = await request<unknown>(`/reports/analysis/${encodeURIComponent(id)}`);
      if (!alive.current) return;
      const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' }));
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = `sentinel-analysis-${id}.json`; anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) { if (alive.current) setError(message(err)); }
    finally { if (alive.current) setBusy(false); }
  }

  return <>
    <div className="info-strip"><span>Analise artefatos de um ativo autorizado. O envio exige escopos de análise e importação de evidências. Os resultados descrevem o material recebido e registram suas limitações.</span></div>
    {error && <p className="form-error" role="alert">{error}</p>}
    {notice && <p className="plain-note" role="status">{notice}</p>}
    {canCreate && <section className="panel section-gap">
      <div className="panel-header"><h2>Nova análise de artefato</h2><span className="badge">IMPORTAÇÃO AUTORIZADA</span></div>
      <form className="module-form" onSubmit={create}>
        <div className="module-columns">
          <label>Ativo para análise<select aria-label="Ativo para análise" required value={assetId} disabled={busy} onChange={event => setAssetId(event.target.value)}><option value="">Selecione um ativo</option>{assets.map(asset => <option value={asset.id} key={asset.id}>{asset.name} · {asset.environment}</option>)}</select></label>
          <label>Tipo de análise<select aria-label="Tipo de análise" value={kind} disabled={busy} onChange={event => changeKind(event.target.value as AnalysisKind)}>{choices.map(item => <option value={item.value} key={item.value}>{item.label}</option>)}</select></label>
        </div>
        <p>{choice.description}</p><p><strong>Formatos aceitos:</strong> {choice.format}.</p>
        {choice.example !== undefined && <details><summary>Ver formato de entrada</summary><p>Modelo de estrutura. Substitua os valores pelos dados da sua coleta.</p><pre className="module-report">{JSON.stringify(choice.example, null, 2)}</pre></details>}
        {kind === 'malware' && <label><span><input style={{ width: 'auto', marginRight: 8 }} type="checkbox" checked={binary} disabled={busy} onChange={event => { ++uploadGeneration.current; setBinary(event.target.checked); setContent(''); }} />Tratar arquivo como binário (não será executado)</span></label>}
        <label>Selecionar artefato<input type="file" disabled={busy} onChange={event => void upload(event)} /><small>Até 1 MiB de conteúdo enviado. Binários usam envelope Base64 e têm limite menor.</small></label>
        <div className="module-columns"><label>Nome do artefato<input required maxLength={240} value={name} disabled={busy} placeholder="package-lock.json" onChange={event => setName(event.target.value)} /></label><label>Tipo do arquivo<input required maxLength={100} value={mediaType} disabled={busy} placeholder="application/json" onChange={event => setMediaType(event.target.value)} /></label></div>
        <label>Conteúdo do artefato<textarea aria-label="Conteúdo do artefato" aria-describedby="analysis-byte-count" required value={content} disabled={busy} spellCheck={false} placeholder="Selecione um arquivo ou cole o conteúdo exportado." onChange={event => setContent(event.target.value)} /><small id="analysis-byte-count">{byteCount.toLocaleString('pt-BR')} / 1.048.576 bytes</small></label>
        <button className="button primary" disabled={busy || assets.length === 0 || byteCount > maxBytes}>{busy ? 'Processando…' : 'Analisar e preservar evidência'}</button>
        {!assets.length && <p>Cadastre um ativo e seus escopos em Assets antes de enviar.</p>}
      </form>
    </section>}

    {detail && <section className="panel section-gap" aria-label="Resultado da análise">
      <div className="panel-header"><div><h2>Resultado da análise</h2><span className="module-small">{detail.report.input.name} · {detail.report.format}</span></div><button className="button secondary" disabled={busy} onClick={() => void download()}>Baixar relatório da análise</button></div>
      <div className="module-form"><p>{detail.report.summary}</p><p>Ativo: {assets.find(asset => asset.id === detail.assetId)?.name ?? detail.assetId}</p><p className="mono module-hash">SHA-256: {detail.report.input.sha256}</p></div>
      <div className="table-scroll"><table><thead><tr><th>Métrica</th><th>Valor</th></tr></thead><tbody>{detail.report.facts.map((item, index) => <tr key={index}><td>{item.label}</td><td>{String(item.value)}</td></tr>)}</tbody></table></div>
      <div className="panel-header"><h3>Achados</h3><span className="badge">{detail.report.findings.length} REGISTROS</span></div>
      {detail.report.findings.length ? <div className="table-scroll"><table><thead><tr><th>Achado e recomendação</th><th>Severidade</th><th>Localização / regra</th><th>Origem</th></tr></thead><tbody>{detail.report.findings.map(item => <tr key={item.id}><td><strong>{item.title}</strong><small className="module-small">{item.recommendation}</small></td><td><span className={`badge ${item.severity}`}>{severity[item.severity] ?? item.severity}</span></td><td><span className="mono">{item.location}</span><small className="module-small">{item.ruleId}</small></td><td>{item.provenance === 'imported_tool' ? 'Ferramenta importada' : 'Regra local'}<small className="module-small">Confiança {item.confidence === 'high' ? 'alta' : 'média'}</small></td></tr>)}</tbody></table></div> : <p className="plain-note">Nenhum achado nas regras aplicadas ao artefato. Isso não comprova segurança do ativo.</p>}
      {detail.report.timeline && <><div className="panel-header"><h3>Linha do tempo</h3><span className="badge">{detail.report.timeline.length} EVENTOS</span></div><div className="table-scroll"><table><thead><tr><th>Instante</th><th>Evento</th><th>Fonte</th><th>Hash do registro</th></tr></thead><tbody>{detail.report.timeline.slice(0, 100).map((item, index) => <tr key={`${item.evidenceHash}:${index}`}><td>{date(item.occurredAt)}</td><td>{item.eventType}</td><td>{item.source}</td><td className="mono module-hash">{item.evidenceHash}</td></tr>)}</tbody></table></div>{detail.report.timeline.length > 100 && <p className="plain-note">A tela mostra os primeiros 100 eventos. Baixe o relatório para consultar a linha do tempo completa.</p>}</>}
      <div className="module-form"><h3>Limites desta análise</h3>{detail.report.limitations.map((item, index) => <p key={index}>{item}</p>)}</div>
    </section>}

    <section className="panel section-gap"><div className="panel-header"><h2>Histórico de análises especializadas</h2><span className="badge">ÚLTIMAS 100</span></div>
      {loading && <p className="plain-note" role="status">Carregando registros…</p>}
      <div className="table-scroll"><table><thead><tr><th>Tipo / ativo</th><th>Achados</th><th>Registro</th><th>Resultado</th></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><strong>{choices.find(item => item.value === row.kind)?.label ?? row.kind}</strong><small className="module-small">{assets.find(asset => asset.id === row.assetId)?.name ?? row.assetId}</small></td><td>{row.findingCount}</td><td>{date(row.createdAt)}</td><td><button className="text-button" disabled={busy} onClick={() => void inspect(row.id)}>Abrir análise</button></td></tr>)}</tbody></table></div>
      {!loading && !rows.length && <p className="plain-note">Nenhuma análise de artefato registrada nesta empresa.</p>}
    </section>
  </>;
}
