import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { TrustShieldHero } from '../components/hero/TrustShieldHero';
import { AnalyzerConsole } from '../components/analyzer/AnalyzerConsole';
import {
  ProductOverview, HowItWorks, TrustArchitecture, TechnologySection, Footer,
} from '../components/sections';
import type { AnalysisResult, HistoryItem } from '../types';
import { api } from '../services/api';
import { riskColor, riskDisplayLabel } from '../utils/risk';

export function Dashboard() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const navigate = useNavigate();

  const loadHistory = () => {
    api.history().then(setHistory).catch(() => {});
  };

  useEffect(() => {
    loadHistory();
  }, []);

  useEffect(() => {
    if (result) loadHistory();
  }, [result?.analysisId]); // eslint-disable-line react-hooks/exhaustive-deps

  const formatTime = (isoString: string) => {
    try {
      const date = new Date(isoString);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ', ' + date.toLocaleDateString();
    } catch {
      return isoString;
    }
  };

  return (
    <div>
      <a href="#analyze" className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-[60] focus:bg-mist-100 focus:text-ink-950 focus:px-3 focus:py-2 focus:rounded">
        Skip to analyzer
      </a>
      <TrustShieldHero />

      <main>
        <ProductOverview />

        <section id="analyze" aria-labelledby="analyze-h" className="border-t border-white/5 scroll-mt-14">
          <div className="max-w-shell mx-auto px-4 sm:px-6 py-20 sm:py-28 space-y-8">
            <div className="max-w-2xl">
              <p className="text-xs font-mono tracking-[0.25em] text-mist-500">ANALYZER CONSOLE</p>
              <h2 id="analyze-h" className="mt-2 text-3xl sm:text-4xl font-extrabold tracking-tight">ANALYZE DIGITAL INPUT</h2>
              <p className="mt-3 text-mist-300 text-sm sm:text-base">
                Submit an input and review the evidence behind the assessment. Every check runs against the live analysis service.
              </p>
            </div>
            <AnalyzerConsole result={result} onResult={setResult} />
          </div>
        </section>

        <HowItWorks />
        <TrustArchitecture />

        <section aria-labelledby="history-h" className="border-t border-white/5">
          <div className="max-w-shell mx-auto px-4 sm:px-6 py-20 sm:py-28">
            <div className="max-w-2xl">
              <p className="text-xs font-mono tracking-[0.25em] text-mist-500">ACTIVITY</p>
              <h2 id="history-h" className="mt-2 text-3xl sm:text-4xl font-extrabold tracking-tight">RECENT ANALYSES</h2>
            </div>
            <div className="mt-8 surface rounded-2xl p-5 sm:p-6">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-mist-500 font-mono">{history.length} stored records</span>
              </div>
              {history.length === 0 ? (
                <div className="rounded-lg border border-white/5 px-4 py-8 text-center">
                  <p className="font-mono text-xs tracking-widest text-mist-500">NO ANALYSES YET</p>
                  <p className="mt-1.5 text-sm text-mist-300">Your completed analyses will appear here.</p>
                </div>
              ) : (
                <ul className="divide-y divide-white/5 list-none">
                  {history.map((h) => (
                    <li key={h.analysisId}>
                      <button
                        onClick={() => navigate(`/analysis/${h.analysisId}`)}
                        className="w-full py-3 px-2 -mx-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-white/[0.03] rounded-xl cursor-pointer transition-colors text-left"
                      >
                        <span className="flex items-center gap-3 min-w-0">
                          <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-white/5 border border-white/10 text-mist-300">
                            {h.inputType}
                          </span>
                          <span className="text-sm text-mist-100 truncate max-w-md font-mono">
                            {h.inputSummary || h.analysisId.slice(0, 8)}
                          </span>
                        </span>
                        <span className="flex items-center gap-3 self-end sm:self-auto shrink-0">
                          <span className={`text-[11px] px-2.5 py-0.5 rounded-full font-mono font-bold border ${riskColor(h.riskLevel)}`}>
                            {riskDisplayLabel(h.riskLevel)}{h.riskScore != null ? ` ${h.riskScore}/100` : ''}
                          </span>
                          <span className="text-xs text-mist-500">{formatTime(h.createdAt)}</span>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </section>

        <TechnologySection />
      </main>

      <Footer />
    </div>
  );
}
