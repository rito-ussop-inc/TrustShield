import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import type { AnalysisResult } from '../types';
import { api } from '../services/api';
import { RiskBadge, RiskScore, FindingsList, EvidencePanel, RecommendationCard, ProviderStatus, LimitationsPanel } from '../components/result';

export function ResultView({ result }: { result: AnalysisResult }) {
  return (
    <div className="space-y-4">
      <div className="bg-white rounded-2xl border p-5 flex flex-col md:flex-row gap-6">
        <div className="flex-1 space-y-3">
          <div className="text-xs text-slate-500">Input type: <b>{result.inputType}</b> · ID: <span className="font-mono">{result.analysisId.slice(0, 8)}</span></div>
          <RiskBadge level={result.riskLevel} />
          {result.decodedPayload && (
            <p className="text-sm bg-slate-50 border rounded p-2 break-all"><b>Decoded QR ({result.payloadType}):</b> {result.decodedPayload}</p>
          )}
          {result.fileSha256 && (
            <p className="text-xs font-mono bg-slate-50 border rounded p-2 break-all">SHA-256: {result.fileSha256}</p>
          )}
          <FindingsList findings={result.findings} />
        </div>
        <div className="w-full md:w-72 space-y-3">
          <div className="bg-white rounded-xl border p-4"><RiskScore score={result.riskScore} level={result.riskLevel} /></div>
          {result.confidence != null && <p className="text-xs text-slate-500">confidence: {result.confidence}</p>}
        </div>
      </div>
      <EvidencePanel evidence={result.evidence} />
      <div className="grid md:grid-cols-2 gap-4">
        <RecommendationCard items={result.recommendation} />
        <LimitationsPanel items={result.limitations} />
      </div>
      <ProviderStatus status={result.providerStatus} />
    </div>
  );
}

export function ResultPage() {
  const { id } = useParams();
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    // try backend stored record; fallback message
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
