/**
 * WITNESS API client.
 *
 * Every call goes to the same origin under `/api/witness/*`:
 * - `next dev` / `next start`: rewritten to the backend by next.config.ts
 *   (WITNESS_BACKEND_URL, default http://localhost:8000);
 * - docker compose: the Caddy gateway strips the prefix and proxies to the
 *   backend container.
 *
 * Auth: when the backend runs with WITNESS_AUTH_MODE=token, a bearer token is
 * read from localStorage key `witness.token` (set it from the System tab) or
 * from NEXT_PUBLIC_WITNESS_API_TOKEN. In dev mode (`none`) the optional
 * identity in localStorage `witness.user` is sent as X-Witness-User.
 */
export const API_BASE = '/api/witness';

export function apiUrl(path: string, params?: Record<string, string | number | boolean | undefined>) {
  const url = new URL(`${API_BASE}${path}`, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

function readStorage(key: string): string | null {
  if (typeof window === 'undefined') return null; // server-side prerender
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function setStoredCredential(key: 'witness.token' | 'witness.user', value: string) {
  try {
    if (value) window.localStorage.setItem(key, value);
    else window.localStorage.removeItem(key);
  } catch {
    /* storage unavailable (private mode) — credentials just won't persist */
  }
}

export function getStoredCredential(key: 'witness.token' | 'witness.user'): string {
  return readStorage(key) || '';
}

function authHeaders(): Record<string, string> {
  const token = readStorage('witness.token') || process.env.NEXT_PUBLIC_WITNESS_API_TOKEN || '';
  const user = readStorage('witness.user');
  const h: Record<string, string> = {};
  if (token) h['Authorization'] = `Bearer ${token}`;
  if (user) h['X-Witness-User'] = user;
  return h;
}

async function fetchJson<T = any>(path: string, options?: RequestInit & { params?: Record<string, any> }): Promise<T> {
  const url = apiUrl(path, options?.params);
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(options?.headers || {}),
    },
    cache: 'no-store',
  });
  if (!res.ok) {
    const text = await res.text();
    let detail = text;
    try {
      detail = JSON.parse(text).detail ?? text;
    } catch {
      /* not JSON */
    }
    throw new Error(`API ${res.status}: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
  }
  if (res.status === 204) return null as any;
  return res.json();
}

export const api = {
  health: () => fetchJson<{ status: string; version: string; auth_mode?: string }>('/health'),
  whoami: () => fetchJson<{ user_id: string; role: string | null; authenticated: boolean; auth_mode: string }>('/auth/whoami'),

  // Scenarios
  loadScenario: (key: string) =>
    fetchJson<{ id: string; name: string }>('/scenarios/load', {
      method: 'POST',
      params: { scenario_key: key },
    }),
  listScenarios: () => fetchJson<any[]>('/scenarios'),
  availableScenarios: () => fetchJson<any[]>('/scenarios/available'),

  // Demo
  flagshipDemo: (body: { max_iterations?: number }) =>
    fetchJson<any>('/demo/flagship', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  // Benchmarks
  runBenchmarks: (body: { scenario_id?: string; model_name?: string } = {}) =>
    fetchJson<any>('/benchmarks/run', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  listBenchmarks: () => fetchJson<any[]>('/benchmarks'),
  runBaseline: (scenarioId: string) =>
    fetchJson<any>('/benchmarks/run-baseline', { method: 'POST', params: { scenario_id: scenarioId } }),

  // Investigations
  listInvestigations: () => fetchJson<any[]>('/investigations'),
  createInvestigation: (body: { title: string; objective: string; incident_id?: string; mode?: string }) =>
    fetchJson<{ id: string }>('/investigations', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  getInvestigation: (id: string) => fetchJson<any>(`/investigations/${id}`),
  runInvestigation: (id: string, body: { scenario_id?: string; max_iterations?: number; background?: boolean }) =>
    fetchJson<any>(`/investigations/${id}/run`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  pauseInvestigation: (id: string) => fetchJson<any>(`/investigations/${id}/pause`, { method: 'POST' }),
  resumeInvestigation: (id: string, body: any) =>
    fetchJson<any>(`/investigations/${id}/resume`, { method: 'POST', body: JSON.stringify(body) }),
  cancelInvestigation: (id: string) => fetchJson<any>(`/investigations/${id}/cancel`, { method: 'POST' }),
  investigationGaps: (id: string) => fetchJson<any[]>(`/investigations/${id}/gaps`),
  investigationCoverage: (id: string) => fetchJson<any>(`/investigations/${id}/coverage`),
  whatWouldChangeMind: (id: string) => fetchJson<any[]>(`/investigations/${id}/what-would-change-mind`),
  integrity: (id: string) => fetchJson<any>(`/investigations/${id}/integrity`),

  // Incidents
  listIncidents: () => fetchJson<any[]>('/incidents'),
  createIncident: (body: { title: string; summary?: string; severity?: string; scope?: string }) =>
    fetchJson<{ id: string }>('/incidents', { method: 'POST', body: JSON.stringify(body) }),

  // Evidence
  listEvidence: (investigationId: string) =>
    fetchJson<any[]>('/evidence', { params: { investigation_id: investigationId } }),

  // Timeline
  listTimeline: (investigationId: string) =>
    fetchJson<any[]>('/timeline', { params: { investigation_id: investigationId } }),

  // Graph
  getGraph: (investigationId: string) =>
    fetchJson<any>('/graph', { params: { investigation_id: investigationId } }),

  // Hypotheses
  listHypotheses: (investigationId: string) =>
    fetchJson<any[]>('/hypotheses', { params: { investigation_id: investigationId } }),
  explainHypothesis: (hypothesisId: string) =>
    fetchJson<{ text: string; source: 'model' | 'deterministic'; model?: string | null;
      grounding: string; cited_evidence_ids: string[]; model_unavailable_reason?: string }>(
      `/hypotheses/${hypothesisId}/explain`, { method: 'POST' }),
  listModelExecutions: (investigationId?: string) =>
    fetchJson<any[]>('/models/executions', { params: { investigation_id: investigationId } }),
  challengeHypothesis: (investigationId: string, hypothesisId: string) =>
    fetchJson<any>(`/hypotheses/${hypothesisId}/challenge`, { params: { investigation_id: investigationId } }),

  // Actions
  listActions: (investigationId?: string, status?: string) =>
    fetchJson<any[]>('/actions', { params: { investigation_id: investigationId, status } }),
  proposeAction: (investigationId: string, body: any) =>
    fetchJson<any>('/actions/propose', {
      method: 'POST',
      body: JSON.stringify(body),
      params: { investigation_id: investigationId },
    }),
  approveAction: (body: { action_id: string; approver_role: string; approver_id?: string; reason?: string }) =>
    fetchJson<any>('/actions/approve', { method: 'POST', body: JSON.stringify(body) }),
  rejectAction: (body: { action_id: string; approver_role: string; approver_id?: string; reason: string }) =>
    fetchJson<any>('/actions/reject', { method: 'POST', body: JSON.stringify(body) }),
  executeAction: (body: { action_id: string }) =>
    fetchJson<any>('/actions/execute', { method: 'POST', body: JSON.stringify(body) }),
  listApprovals: (status?: string) =>
    fetchJson<any[]>('/approvals', { params: { status } }),

  // OT
  listOtAssets: () => fetchJson<any[]>('/ot/assets'),
  otSafetyAssessment: (body: any) =>
    fetchJson<any>('/ot/safety-assessment', { method: 'POST', body: JSON.stringify(body) }),

  // Reports
  generateReport: (investigationId: string, audience: string) =>
    fetchJson<any>('/reports/generate', {
      method: 'POST',
      params: { investigation_id: investigationId, audience },
    }),

  // Audit
  listAudit: (investigationId?: string, limit = 100) =>
    fetchJson<any[]>('/audit', { params: { investigation_id: investigationId, limit } }),

  // Agents / Tools / Models
  listAgents: () => fetchJson<any[]>('/agents'),
  listTools: () => fetchJson<any[]>('/tools'),
  listModels: () => fetchJson<any>('/models'),

  // ATT&CK
  attackEnterprise: () => fetchJson<any>('/attack/enterprise'),
  attackIcs: () => fetchJson<any>('/attack/ics'),

  // Assets
  listAssets: () => fetchJson<any[]>('/assets'),
  getAsset: (id: string) => fetchJson<any>(`/assets/${id}`),

  // Threat intel
  listThreatIntel: (indicatorType?: string) =>
    fetchJson<any[]>('/threat-intel', { params: { indicator_type: indicatorType } }),

  // Hunting
  hunt: (body: { investigation_id: string; objective: string }) =>
    fetchJson<any>('/hunting', { method: 'POST', body: JSON.stringify(body) }),

  // System
  reset: () => fetchJson<any>('/system/reset', { method: 'POST' }),
};
