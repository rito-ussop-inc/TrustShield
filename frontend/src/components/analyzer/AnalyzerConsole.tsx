import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  InputSelector, UrlForm, MessageForm, QrForm, DocumentForm,
  PipelineProgress, type Tab,
} from '../inputs';
import type { AnalysisResult } from '../../types';
import { ResultView } from '../../pages/ResultPage';

/**
 * Analyzer console (PRD §17–21): tabbed real-product interface.
 * All analysis runs against the live backend; no demo defaults.
 */
export function AnalyzerConsole({
  onResult,
  result,
}: {
  onResult: (r: AnalysisResult | null) => void;
  result: AnalysisResult | null;
}) {
  const [tab, setTab] = useState<Tab>('URL');
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();

  const switchTab = (t: Tab) => {
    setTab(t);
    setBusy(false);
    onResult(null);
  };

  return (
    <div className="surface rounded-2xl p-5 sm:p-7 space-y-5">
      <InputSelector tab={tab} setTab={switchTab} />
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === 'URL' && <UrlForm onBusy={setBusy} onResult={(r) => { onResult(r); }} />}
        {tab === 'MESSAGE' && <MessageForm onBusy={setBusy} onResult={(r) => { onResult(r); }} />}
        {tab === 'QR' && <QrForm onBusy={setBusy} onResult={(r) => { onResult(r); }} />}
        {tab === 'DOCUMENT' && <DocumentForm onBusy={setBusy} onResult={(r) => { onResult(r); }} />}
      </div>

      {busy && <PipelineProgress tab={tab} />}

      {!busy && !result && (
        <div className="rounded-lg border border-white/5 px-4 py-6 text-center">
          <p className="font-mono text-xs tracking-widest text-mist-500">NO ANALYSIS YET</p>
          <p className="mt-1.5 text-sm text-mist-300">Submit a URL, QR code, message, or document to begin.</p>
        </div>
      )}

      {!busy && result && (
        <div className="space-y-4 pt-1">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <h3 className="font-mono text-xs tracking-widest text-mist-300">TRUST ASSESSMENT</h3>
            <button
              onClick={() => navigate(`/analysis/${result.analysisId}`)}
              className="text-xs text-mist-300 hover:text-mist-100 underline underline-offset-4"
            >
              Open standalone result page →
            </button>
          </div>
          <ResultView result={result} />
        </div>
      )}
    </div>
  );
}
