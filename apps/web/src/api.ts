export type RecordData = Record<string, unknown>;
export interface Session { user: { id: string; email: string; role: string; organizationId: string }; csrfToken: string; activeOrganization?: { id: string; name: string } }
export interface Asset { id: string; name: string; kind: string; environment: string; criticality: number; projectId?: string; createdAt?: string }
export interface Overview { assets: number; findings: number; evidence: number; scans: number; highFindings: number; recentEvents: RecordData[]; generatedAt: string; source: string }

export class ApiError extends Error {
  constructor(message: string, public status: number, public code = 'REQUEST_FAILED') { super(message); }
}

export async function request<T>(path: string, options: { method?: string; body?: unknown; csrfToken?: string; timeoutMs?:number } = {}): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), options.timeoutMs??30_000);
  try {
    const response = await fetch(`/api${path}`, {
      method: options.method ?? 'GET', credentials: 'same-origin', signal: controller.signal,
      headers: { ...(options.body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(options.csrfToken ? { 'x-csrf-token': options.csrfToken } : {}) },
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
    });
    const result = response.status === 204 ? null : await response.json().catch(() => null);
    if (!response.ok) throw new ApiError(result?.error?.message ?? `Não foi possível concluir a solicitação (${response.status}).`, response.status, result?.error?.code);
    return result as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(error instanceof Error && error.name === 'AbortError' ? 'O servidor demorou a responder. Verifique a conexão e tente novamente.' : 'Não foi possível acessar a API local. Verifique se o serviço Sentinel está iniciado.', 0);
  } finally { window.clearTimeout(timeout); }
}

export const text = (item: RecordData, ...keys: string[]): string => {
  for (const key of keys) if (typeof item[key] === 'string' || typeof item[key] === 'number') return String(item[key]);
  return '';
};
export const date = (value: unknown): string => {
  if (typeof value !== 'string') return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? '—' : parsed.toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
};
export const message = (error: unknown) => error instanceof Error ? error.message : 'Ocorreu um erro inesperado.';
