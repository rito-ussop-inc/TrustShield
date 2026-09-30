import type { AnalysisResult } from '../types';

const BASE = '';

async function handle(res: Response) {
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error((body as { detail?: string }).detail || `Request failed (${res.status})`);
  }
  return res.json();
}

export const api = {
  analyzeUrl: (url: string): Promise<AnalysisResult> =>
    fetch(`${BASE}/api/v1/analyze/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    }).then(handle),

  analyzeMessage: (text: string): Promise<AnalysisResult> =>
    fetch(`${BASE}/api/v1/analyze/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    }).then(handle),

  analyzeQr: (file: File): Promise<AnalysisResult> => {
    const fd = new FormData();
    fd.append('file', file);
    return fetch(`${BASE}/api/v1/analyze/qr`, { method: 'POST', body: fd }).then(handle);
  },

  analyzeDocument: (file: File, referenceSha256?: string): Promise<AnalysisResult> => {
    const fd = new FormData();
    fd.append('file', file);
    if (referenceSha256) fd.append('reference_sha256', referenceSha256);
    return fetch(`${BASE}/api/v1/analyze/document`, { method: 'POST', body: fd }).then(handle);
  },

  history: (): Promise<{ analysisId: string; inputType: string; riskLevel: string; riskScore: number | null; createdAt: string }[]> =>
    fetch(`${BASE}/api/v1/analyses?limit=20`).then(handle),

  getAnalysis: (id: string): Promise<AnalysisResult> =>
    fetch(`${BASE}/api/v1/analyses/${id}`).then(handle),

  providers: (): Promise<Record<string, string>> =>
    fetch(`${BASE}/api/v1/providers/status`).then(handle)
};
