import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { InputSelector, UrlForm, MessageForm, QrForm, DocumentForm, type Tab } from '../components/inputs';
import type { AnalysisResult } from '../types';
import { ResultView } from './ResultPage';
import { api } from '../services/api';
import { useEffect } from 'react';

export function Dashboard() {
  const [tab, setTab] = useState<Tab>('URL');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<{ analysisId: string; inputType: string; riskLevel: string; riskScore: number | null; createdAt: string }[]>([]);
  const navigate = useNavigate();

  useEffect(() => {
    api.history().then(setHistory).catch(() => {});
  }, [result]);

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 space-y-6">
      <header className="text-center space-y-2">
        <div className="inline-flex items-center gap-2 text-shield-600 font-bold text-sm tracking-widest">🛡️ TRUSTSHIELD</div>
        <h1 className="text-3xl font-bold">Verify Before You Trust</h1>
        <p className="text-slate-600 text-sm max-w-2xl mx-auto">
          Paste a link, message, QR code or document. TrustShield combines deterministic checks, ML signals and
          threat intelligence into one explainable risk assessment. Unknown is never called “safe”.
        </p>
      </header>

      <div className="bg-white rounded-2xl border p-5 space-y-4 shadow-sm">
        <InputSelector tab={tab} setTab={(t) => { setTab(t); setResult(null); }} />
        {tab === 'URL' && <UrlForm onResult={(r) => { setResult(r); }} />}
        {tab === 'MESSAGE' && <MessageForm onResult={(r) => { setResult(r); }} />}
        {tab === 'QR' && <QrForm onResult={(r) => { setResult(r); }} />}
        {tab === 'DOCUMENT' && <DocumentForm onResult={(r) => { setResult(r); }} />}
      </div>

      {result && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">Latest result</h2>
            <button onClick={() => navigate(`/analysis/${result.analysisId}`)} className="text-sm text-shield-600 underline">
              Open full result page →
            </button>
          </div>
          <ResultView result={result} />
        </div>
      )}

      <div className="bg-white rounded-2xl border p-5">
        <h2 className="font-semibold mb-2">Recent analyses</h2>
        {history.length === 0 ? (
          <p className="text-sm text-slate-500">No history yet — run your first verification above.</p>
        ) : (
          <ul className="text-sm divide-y">
            {history.map((h) => (
              <li key={h.analysisId} className="py-2 flex items-center justify-between">
                <button className="text-left hover:underline" onClick={() => navigate(`/analysis/${h.analysisId}`)}>
                  <span className="font-mono text-xs text-slate-500">{h.analysisId.slice(0, 8)}</span>{' '}
                  <span className="font-medium">{h.inputType}</span> · {h.riskLevel} ({h.riskScore ?? '—'})
                </button>
                <span className="text-xs text-slate-400">{new Date(h.createdAt).toLocaleString()}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <footer className="text-center text-xs text-slate-400">
        Never enter credentials or pay from an unverified link. Verify through an independent official channel.
      </footer>
    </div>
  );
}
