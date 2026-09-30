import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import type { AnalysisResult } from '../types';
import { api } from '../services/api';
import {
  RiskBadge,
  RiskScore,
  PlainLanguageBanner,
  UrlDetailsCard,
  FindingsList,
  EvidencePanel,
  RecommendationCard,
  ProviderStatus,
  LimitationsPanel,
} from '../components/result';

export function ResultView({ result }: { result: AnalysisResult }) {
  const [showTechnical, setShowTechnical] = useState(true);

  return (
    <div className="space-y-4">
      {result.plainSummary && (
        <PlainLanguageBanner summary={result.plainSummary} level={result.riskLevel} />
      )}

      <div className="surface rounded-xl p-5 flex flex-col md:flex-row gap-6">
        <div className="flex-1 space-y-3 min-w-0">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="text-xs text-mist-500 font-mono">
              Input type: <b className="text-mist-100">{result.inputType}</b> · ID: <span className="font-mono">{result.analysisId.slice(0, 8)}</span>
            </div>
            <RiskBadge level={result.riskLevel} />
          </div>

          {result.decodedPayload && (
            <p className="text-sm bg-ink-950 border border-white/10 rounded-lg p-2.5 break-all">
              <b>Decoded QR ({result.payloadType}):</b>{' '}
              <span className="font-mono text-xs">{result.decodedPayload}</span>
            </p>
          )}
          {result.fileSha256 && (
            <p className="text-xs font-mono bg-ink-950 border border-white/10 rounded-lg p-2.5 break-all text-mist-300">SHA-256: {result.fileSha256}</p>
          )}

          <UrlDetailsCard
            rawUrl={result.rawUrl}
            normalizedUrl={result.normalizedUrl}
            warnings={result.normalizationWarnings}
            modelStatus={result.modelStatus}
            modelVersion={result.modelVersion}
          />
        </div>

        <div className="w-full md:w-72 shrink-0 space-y-3">
          <div className="surface-raised rounded-xl p-4">
            <RiskScore score={result.riskScore} level={result.riskLevel} scoringVersion={result.scoringVersion} />
          </div>
          {result.confidence != null && <p className="text-xs text-mist-500">Assessed confidence: {result.confidence}</p>}
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <RecommendationCard items={result.recommendation} />
        <LimitationsPanel items={result.limitations} />
      </div>

      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono tracking-widest text-mist-500">TECHNICAL ANALYSIS</h3>
          <button
            onClick={() => setShowTechnical(!showTechnical)}
            className="text-xs text-mist-300 hover:text-mist-100 underline underline-offset-4"
            aria-expanded={showTechnical}
          >
            {showTechnical ? 'Hide technical diagnostics ▴' : 'Show technical diagnostics ▾'}
          </button>
        </div>

        {showTechnical && (
          <div className="space-y-4">
            <FindingsList findings={result.findings} />
            <EvidencePanel evidence={result.evidence} />
            <ProviderStatus status={result.providerStatus} results={result.providerResults} />
          </div>
        )}
      </div>
    </div>
  );
}

export function ResultPage() {
  const { id } = useParams();
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    api.getAnalysis(id).then(setResult).catch((e) => setError((e as Error).message));
  }, [id]);

  return (
    <div className="max-w-shell mx-auto px-4 sm:px-6 py-24 space-y-4">
      <Link to="/" className="text-sm text-mist-300 hover:text-mist-100 underline underline-offset-4">← Back to analyzer</Link>
      <h1 className="text-2xl font-extrabold tracking-tight">Analysis result</h1>
      {error && (
        <p role="alert" className="text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
          Analysis unavailable — the stored result could not be loaded ({error}). If you just analyzed, use the analyzer result view.
        </p>
      )}
      {result ? <ResultView result={result} /> : !error && <p className="text-sm text-mist-500">Loading…</p>}
    </div>
  );
}
