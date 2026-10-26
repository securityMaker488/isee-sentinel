import { useEffect, useMemo, useRef, useState } from 'react';
import { date, message, request } from './api';

interface Node { id: string; type: string; label: string; assetId?: string; data: Record<string, unknown> }
interface Edge { id: string; from: string; to: string; relation: string }
interface Graph { nodes: Node[]; edges: Edge[]; truncated: boolean; counts: { nodes: number; edges: number; byType: Record<string, number> }; limitations: string[] }
const types: Record<string, string> = { organization: 'Empresa', project: 'Projeto', asset: 'Ativo', scan: 'SecureBuild', finding: 'Achado', incident: 'Incidente', alert: 'Alerta', analysis: 'Análise de artefato', remediation: 'Correção de artefato', evidence: 'Evidência' };
const relations: Record<string, string> = { has_project: 'contém projeto', has_asset: 'contém ativo', latest_static_scan: 'última análise estática', produced_finding: 'produziu achado', has_incident: 'tem incidente', has_alert: 'tem alerta', has_artifact_analysis: 'tem análise de artefato', has_artifact_remediation: 'tem correção de artefato', has_evidence: 'preserva evidência', supported_by: 'sustentado por', analyzed_evidence: 'analisou evidência', original_evidence: 'original preservado', proposed_evidence: 'proposta preservada', case_evidence: 'evidência do caso' };
const columns: Record<string, number> = { organization: 0, project: 1, asset: 2, scan: 3, incident: 3, analysis: 3, remediation: 3, finding: 4, alert: 4, evidence: 5 };
const colors: Record<string, string> = { organization: '#c4e871', project: '#81b8e9', asset: '#75d3ab', scan: '#a3aee5', incident: '#f3bd75', analysis: '#ba9ed9', remediation: '#7bd0d6', finding: '#efb28b', alert: '#e99797', evidence: '#acb7ae' };
const fields: Record<string, string> = { kind: 'Tipo', environment: 'Ambiente', criticality: 'Criticidade do ativo', createdAt: 'Registrado em', findingCount: 'Achados', ruleId: 'Regra', severity: 'Severidade', confidence: 'Confiança', status: 'Estado', synthetic: 'Sintético', target: 'Alvo da correção', sha256: 'SHA-256 armazenado', mediaType: 'Tipo de arquivo', bytes: 'Bytes' };
const words: Record<string, string> = { lab: 'Laboratório', production: 'Produção', staging: 'Homologação', high: 'Alta', medium: 'Média', low: 'Baixa', critical: 'Crítica', info: 'Informativa', unknown: 'Não determinado', stored_lab_artifact: 'Cópia preservada em laboratório', open: 'Aberto', investigating: 'Em investigação', closed: 'Encerrado', resolved: 'Resolvido', proposed: 'Proposta', approved: 'Aprovada', applied: 'Cópia atualizada', verified: 'Cópia verificada', rolled_back: 'Cópia restaurada', no_change: 'Sem mudança', manual_review: 'Revisão manual' };
function display(value: unknown): string { return typeof value === 'boolean' ? (value ? 'Sim' : 'Não') : value === null || value === undefined ? '—' : words[String(value)] ?? String(value); }

export default function RiskGraphView() {
  const [graph, setGraph] = useState<Graph | null>(null), [selected, setSelected] = useState('');
  const [type, setType] = useState('all'), [asset, setAsset] = useState('all');
  const [error, setError] = useState(''), [busy, setBusy] = useState(false);
  const alive = useRef(true), generation = useRef(0);
  async function load() {
    const current = ++generation.current;
    setBusy(true); setError('');
    try {
      const result = await request<Graph>('/graph');
      if (alive.current && current === generation.current) { setGraph(result); setSelected(previous => result.nodes.some(item => item.id === previous) ? previous : result.nodes.find(item => item.type === 'asset')?.id ?? result.nodes[0]?.id ?? ''); }
    } catch (err) { if (alive.current && current === generation.current) setError(message(err)); }
    finally { if (alive.current && current === generation.current) setBusy(false); }
  }
  useEffect(() => { alive.current = true; void load(); return () => { alive.current = false; ++generation.current; }; }, []);
  const visible = useMemo(() => {
    if (!graph) return { nodes: [] as Node[], edges: [] as Edge[] };
    const ids = new Set(graph.nodes.filter(node => (type === 'all' || node.type === type) && (asset === 'all' || node.assetId === asset || node.id === asset)).map(node => node.id));
    const ownership = new Set(['has_project', 'has_asset', 'latest_static_scan', 'produced_finding', 'has_incident', 'has_alert', 'has_artifact_analysis', 'has_artifact_remediation', 'has_evidence']);
    let changed = true;
    while (changed) { changed = false; for (const edge of graph.edges) if (ownership.has(edge.relation) && ids.has(edge.to) && !ids.has(edge.from)) { ids.add(edge.from); changed = true; } }
    return { nodes: graph.nodes.filter(node => ids.has(node.id)), edges: graph.edges.filter(edge => ids.has(edge.from) && ids.has(edge.to)) };
  }, [graph, type, asset]);
  const positions = useMemo(() => {
    const slots = new Map<number, number>(), result = new Map<string, { x: number; y: number }>();
    for (const node of visible.nodes) { const column = columns[node.type] ?? 3, row = slots.get(column) ?? 0; slots.set(column, row + 1); result.set(node.id, { x: 100 + column * 195, y: 55 + row * 64 }); }
    return { nodes: result, height: Math.max(250, ...[...slots.values()].map(count => count * 64 + 45)) };
  }, [visible]);
  const node = graph?.nodes.find(item => item.id === selected);
  const risk = node?.data.risk && typeof node.data.risk === 'object' ? node.data.risk as Record<string, unknown> : null;
  const connected = graph?.edges.filter(edge => edge.from === selected || edge.to === selected) ?? [];

  return <>
    <div className="info-strip"><span>RiskGraph conecta os registros existentes da empresa: ativos, análises, achados, incidentes e evidências. As ligações mostram contexto documentado e não comprovam caminhos de ataque.</span></div>
    {error && <p className="form-error" role="alert">{error}</p>}
    <section className="panel section-gap"><div className="panel-header"><h2>Mapa de relações</h2><button className="button secondary" disabled={busy} onClick={() => void load()}>{busy ? 'Carregando…' : 'Atualizar grafo'}</button></div>
      <div className="module-form"><div className="module-columns"><label>Filtrar tipo de registro<select value={type} onChange={event => setType(event.target.value)}><option value="all">Todos os tipos</option>{Object.keys(graph?.counts.byType ?? {}).map(value => <option value={value} key={value}>{types[value] ?? value}</option>)}</select></label><label>Filtrar ativo no grafo<select value={asset} onChange={event => setAsset(event.target.value)}><option value="all">Todos os ativos</option>{graph?.nodes.filter(item => item.type === 'asset').map(item => <option key={item.id} value={item.assetId}>{item.label}</option>)}</select></label></div>
        <p>{visible.nodes.length} nós e {visible.edges.length} ligações visíveis. Filtros mantêm os registros de origem para preservar contexto.</p>
        {graph?.truncated && <p role="status">O conjunto excede os limites do grafo. Este é um recorte dos registros; consulte os módulos de origem para o histórico completo.</p>}
        <div className="module-tabs">{Object.entries(graph?.counts.byType ?? {}).map(([key, count]) => <span className="badge" key={key} style={{ borderColor: colors[key] }}>{types[key] ?? key}: {count}</span>)}</div>
      </div>
      {!!visible.nodes.length && <div style={{ overflow: 'auto', maxHeight: 520, borderTop: '1px solid #26382d', background: '#0a1410' }}>
        <svg width="1180" height={positions.height} viewBox={`0 0 1180 ${positions.height}`} role="group" aria-label="Grafo interativo de registros. Use Tab e Enter para selecionar um nó; uma lista equivalente está disponível abaixo.">
          <defs><marker id="riskgraph-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7" fill="#506959" /></marker></defs>
          {visible.edges.map(edge => { const from = positions.nodes.get(edge.from)!, to = positions.nodes.get(edge.to)!; return <path key={edge.id} d={`M ${from.x + 76} ${from.y} C ${from.x + 115} ${from.y}, ${to.x - 115} ${to.y}, ${to.x - 78} ${to.y}`} fill="none" stroke={edge.from === selected || edge.to === selected ? '#a9d966' : '#3b5143'} strokeWidth={edge.from === selected || edge.to === selected ? 2 : 1} opacity={edge.from === selected || edge.to === selected ? 1 : 0.55} markerEnd="url(#riskgraph-arrow)"><title>{relations[edge.relation] ?? edge.relation}</title></path>; })}
          {visible.nodes.map(item => { const point = positions.nodes.get(item.id)!; return <g key={item.id} role="button" tabIndex={0} aria-label={`${types[item.type] ?? item.type}: ${item.label}`} aria-pressed={item.id === selected} onClick={() => setSelected(item.id)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelected(item.id); } }} style={{ cursor: 'pointer' }}><title>{item.label}</title><rect x={point.x - 76} y={point.y - 23} width="152" height="46" rx="9" fill={item.id === selected ? '#294331' : '#15241b'} stroke={colors[item.type] ?? '#95aa9b'} strokeWidth={item.id === selected ? 3 : 1} /><text x={point.x} y={point.y - 4} textAnchor="middle" fill={colors[item.type] ?? '#c7d9ca'} fontSize="10" fontFamily="sans-serif">{types[item.type] ?? item.type}</text><text x={point.x} y={point.y + 12} textAnchor="middle" fill="#e4eee4" fontSize="11" fontFamily="sans-serif">{item.label.length > 23 ? item.label.slice(0, 22) + '…' : item.label}</text></g>; })}
        </svg>
      </div>}
      {!busy && !visible.nodes.length && <p className="plain-note">Nenhum registro corresponde ao filtro.</p>}
    </section>
    {node && <section className="panel section-gap"><div className="panel-header"><h2>Registro selecionado</h2><span className="badge">{types[node.type] ?? node.type}</span></div><div className="module-form"><h3>{node.label}</h3>
      {risk && <p><strong>Risco da análise estática: {display(risk.level)}</strong>{risk.level !== 'unknown' && typeof risk.score === 'number' ? ` · pontuação ${risk.score}` : ''}<br />{String(risk.reason ?? risk.explanation ?? '')}<br />{String(risk.method ?? '')}</p>}
      <dl>{Object.entries(node.data).filter(([key]) => key !== 'risk').map(([key, value]) => <div key={key} style={{ marginBottom: 12 }}><dt><strong>{fields[key] ?? key}</strong></dt><dd style={{ margin: '4px 0', overflowWrap: 'anywhere' }}>{key === 'createdAt' ? date(value) : display(value)}</dd></div>)}</dl>
      <h3>Relações registradas</h3>{connected.map(edge => { const target = graph?.nodes.find(item => item.id === (edge.from === node.id ? edge.to : edge.from)); return target ? <p key={edge.id}>{edge.from === node.id ? '' : 'Origem: '}{relations[edge.relation] ?? edge.relation} → <button className="text-button" onClick={() => setSelected(target.id)}>{target.label}</button></p> : null; })}{!connected.length && <p>Nenhuma relação neste recorte.</p>}
    </div></section>}
    <section className="panel section-gap"><div className="panel-header"><h2>Lista acessível de registros</h2><span className="badge">{visible.nodes.length} NÓS</span></div><div className="table-scroll"><table><thead><tr><th>Tipo</th><th>Registro</th><th>Relações visíveis</th><th>Inspecionar</th></tr></thead><tbody>{visible.nodes.map(item => <tr key={item.id}><td>{types[item.type] ?? item.type}</td><td>{item.label}</td><td>{visible.edges.filter(edge => edge.from === item.id || edge.to === item.id).length}</td><td><button className="text-button" aria-label={`Inspecionar ${item.label}`} onClick={() => setSelected(item.id)}>Ver relações</button></td></tr>)}</tbody></table></div></section>
    {graph && <section className="panel section-gap"><div className="panel-header"><h2>Escopo e limitações do grafo</h2></div><div className="module-form">{graph.limitations.map((item, index) => <p key={index}>{item}</p>)}</div></section>}
  </>;
}
