import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { InputSelector, UrlForm, MessageForm, QrForm, DocumentForm, type Tab } from '../components/inputs';
import type { AnalysisResult, HistoryItem } from '../types';
import { ResultView } from './ResultPage';
import { api } from '../services/api';
import { riskColor } from '../utils/risk';

export function Dashboard() {
  const [tab, setTab] = useState<Tab>('URL');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const navigate = useNavigate();

  const loadHistory = () => {
    api.history().then(setHistory).catch(() => {});
  };

  useEffect(() => {
    loadHistory();
  }, [result]);

  const formatTime = (isoString: string) => {
    try {
      const date = new Date(isoString);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ', ' + date.toLocaleDateString();
    } catch {
      return isoString;
    }
  };

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
        {tab === 'URL' && <UrlForm onResult={(r) => { setResult(r); loadHistory(); }} />}
        {tab === 'MESSAGE' && <MessageForm onResult={(r) => { setResult(r); loadHistory(); }} />}
        {tab === 'QR' && <QrForm onResult={(r) => { setResult(r); loadHistory(); }} />}
        {tab === 'DOCUMENT' && <DocumentForm onResult={(r) => { setResult(r); loadHistory(); }} />}
      </div>

      {result && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-lg">Latest result</h2>
            <button onClick={() => navigate(`/analysis/${result.analysisId}`)} className="text-sm text-shield-600 hover:underline">
              Open standalone result page →
            </button>
          </div>
          <ResultView result={result} />
        </div>
      )}

      <div className="bg-white rounded-2xl border p-5 shadow-sm space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold text-base">Recent verifications</h2>
          <span className="text-xs text-slate-500">{history.length} stored records</span>
        </div>

        {history.length === 0 ? (
          <p className="text-sm text-slate-500 py-2">No verifications yet — run your first analysis above.</p>
        ) : (
          <div className="divide-y divide-slate-100">
            {history.map((h) => (
              <div
                key={h.analysisId}
                onClick={() => navigate(`/analysis/${h.analysisId}`)}
                className="py-3 px-2 -mx-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-slate-50 rounded-xl cursor-pointer transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-100 border text-slate-700">
                    {h.inputType}
                  </span>
                  <span className="text-sm font-medium text-slate-800 truncate max-w-md font-mono">
                    {h.inputSummary || h.analysisId.slice(0, 8)}
                  </span>
                </div>

                <div className="flex items-center gap-3 self-end sm:self-auto shrink-0">
                  <span className={`text-xs px-2.5 py-0.5 rounded-full font-semibold border ${riskColor(h.riskLevel)}`}>
                    {h.riskLevel} {h.riskScore != null ? `(${h.riskScore}/100)` : ''}
                  </span>
                  <span className="text-xs text-slate-400">{formatTime(h.createdAt)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <footer className="text-center text-xs text-slate-400">
        Never enter credentials or pay from an unverified link. Verify through an independent official channel.
      </footer>
    </div>
  );
}
