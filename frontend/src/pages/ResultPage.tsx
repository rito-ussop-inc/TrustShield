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
      {/* 1. Prominent Plain-English Summary for Everyday Users */}
      {result.plainSummary && (
        <PlainLanguageBanner summary={result.plainSummary} level={result.riskLevel} />
      )}

      {/* 2. Primary Assessment Overview Card */}
      <div className="bg-white rounded-2xl border p-5 flex flex-col md:flex-row gap-6 shadow-sm">
        <div className="flex-1 space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2 text-xs text-slate-500">
            <div>Input type: <b>{result.inputType}</b> · ID: <span className="font-mono">{result.analysisId.slice(0, 8)}</span></div>
            <RiskBadge level={result.riskLevel} />
          </div>

          {result.decodedPayload && (
            <p className="text-sm bg-slate-50 border rounded p-2 break-all">
              <b>Decoded QR ({result.payloadType}):</b> {result.decodedPayload}
            </p>
          )}
          {result.fileSha256 && (
            <p className="text-xs font-mono bg-slate-50 border rounded p-2 break-all">SHA-256: {result.fileSha256}</p>
          )}

          <UrlDetailsCard
            rawUrl={result.rawUrl}
            normalizedUrl={result.normalizedUrl}
            warnings={result.normalizationWarnings}
            modelStatus={result.modelStatus}
            modelVersion={result.modelVersion}
          />
        </div>

        <div className="w-full md:w-72 space-y-3">
          <div className="bg-white rounded-xl border p-4">
            <RiskScore score={result.riskScore} level={result.riskLevel} scoringVersion={result.scoringVersion} />
          </div>
          {result.confidence != null && <p className="text-xs text-slate-500">Assessed confidence: {result.confidence}</p>}
        </div>
      </div>

      {/* 3. Actionable Security Steps & Limitations */}
      <div className="grid md:grid-cols-2 gap-4">
        <RecommendationCard items={result.recommendation} />
        <LimitationsPanel items={result.limitations} />
      </div>

      {/* 4. Collapsible/Expandable Technical Evidence and Provider Diagnostics */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-700">Technical Analysis & Inspection Breakdown</h3>
          <button
            onClick={() => setShowTechnical(!showTechnical)}
            className="text-xs text-shield-600 hover:underline font-medium"
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
    <div className="max-w-5xl mx-auto px-4 py-8 space-y-4">
      <Link to="/" className="text-sm text-shield-600 underline">← Back to dashboard</Link>
      <h1 className="text-2xl font-bold">Analysis result</h1>
      {error && <p className="text-sm text-red-600">Could not load stored analysis ({error}). If you just analyzed, use the dashboard result view.</p>}
      {result ? <ResultView result={result} /> : !error && <p className="text-sm text-slate-500">Loading…</p>}
    </div>
  );
}
