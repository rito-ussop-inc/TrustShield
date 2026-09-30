import type { RiskLevel, ProviderCheckDetail, PlainLanguageSummary } from '../types';
import { riskColor, riskLabel } from '../utils/risk';

export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold border ${riskColor(level)}`}>
      {level} · {riskLabel(level)}
    </span>
  );
}

export function PlainLanguageBanner({
  summary,
  level,
}: {
  summary?: PlainLanguageSummary | null;
  level: RiskLevel;
}) {
  if (!summary) return null;

  const bgBorder =
    level === 'CRITICAL' || level === 'HIGH'
      ? 'bg-red-50 border-red-200 text-red-950'
      : level === 'MEDIUM'
      ? 'bg-amber-50 border-amber-200 text-amber-950'
      : level === 'LOW'
      ? 'bg-emerald-50 border-emerald-200 text-emerald-950'
      : 'bg-slate-50 border-slate-200 text-slate-900';

  const badgeBg =
    level === 'CRITICAL' || level === 'HIGH'
      ? 'bg-red-600 text-white'
      : level === 'MEDIUM'
      ? 'bg-amber-600 text-white'
      : level === 'LOW'
      ? 'bg-emerald-600 text-white'
      : 'bg-slate-600 text-white';

  return (
    <div className={`rounded-2xl border-2 p-5 space-y-3 shadow-sm ${bgBorder}`}>
      <div className="flex items-center justify-between flex-wrap gap-2">
        <span className={`text-xs font-bold uppercase tracking-wider px-2.5 py-1 rounded-full ${badgeBg}`}>
          {summary.verdictBadge || level}
        </span>
        <span className="text-xs opacity-75 font-medium">Simple Explanation for Everyday Users</span>
      </div>

      <h2 className="text-xl font-bold leading-snug">{summary.headline}</h2>
      <p className="text-sm leading-relaxed opacity-90">{summary.explanation}</p>

      {summary.securityNotice && (
        <div className="p-3 bg-white/80 rounded-xl border border-amber-300 text-xs text-amber-900 font-medium">
          {summary.securityNotice}
        </div>
      )}

      <div className="p-3 bg-white/90 rounded-xl border border-slate-200 space-y-1">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-600">What you should do:</div>
        <div className="text-sm font-semibold text-slate-900">{summary.actionAdvice}</div>
      </div>
    </div>
  );
}

export function RiskScore({
  score,
  level,
  scoringVersion,
}: {
  score?: number | null;
  level: RiskLevel;
  scoringVersion?: string | null;
}) {
  const v = score ?? 0;
  const bar =
    level === 'CRITICAL' ? 'bg-red-600' :
    level === 'HIGH' ? 'bg-orange-500' :
    level === 'MEDIUM' ? 'bg-amber-400' :
    level === 'LOW' ? 'bg-emerald-500' : 'bg-slate-400';
  return (
    <div>
      <div className="flex items-baseline gap-2">
        <span className="text-4xl font-bold">{score ?? '—'}</span>
        <span className="text-sm text-slate-500">/ 100</span>
      </div>
      <div className="mt-2 h-3 w-full bg-slate-200 rounded-full overflow-hidden">
        <div className={`h-full ${bar} transition-all`} style={{ width: `${v}%` }} />
      </div>
      <p className="mt-2 text-xs text-slate-500">
        Non-duplicative evidence score ({scoringVersion ?? 'calibrated'}). High scores indicate observed risk; a low score does not guarantee safety.
      </p>
    </div>
  );
}

export function UrlDetailsCard({
  rawUrl,
  normalizedUrl,
  warnings,
  modelStatus,
  modelVersion,
}: {
  rawUrl?: string | null;
  normalizedUrl?: string | null;
  warnings?: string[];
  modelStatus?: string | null;
  modelVersion?: string | null;
}) {
  if (!rawUrl && !normalizedUrl) return null;
  return (
    <div className="bg-slate-50 rounded-xl border p-4 space-y-2 text-sm">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <span className="font-semibold text-slate-700">Target Details</span>
        {modelVersion && (
          <span className={`text-xs px-2 py-0.5 rounded border font-mono ${modelStatus === 'available' ? 'bg-indigo-50 border-indigo-200 text-indigo-700' : 'bg-slate-100 border-slate-300 text-slate-600'}`}>
            Model: {modelVersion} ({modelStatus ?? 'unknown'})
          </span>
        )}
      </div>

      <div className="space-y-1">
        <div className="text-xs text-slate-500">Submitted URL:</div>
        <div className="font-mono text-xs break-all bg-white p-2 rounded border border-slate-200 text-slate-800 select-all">
          {rawUrl || normalizedUrl}
        </div>
      </div>

      {normalizedUrl && rawUrl && normalizedUrl !== rawUrl && (
        <div className="space-y-1">
          <div className="text-xs text-slate-500">Normalized Canonical Form:</div>
          <div className="font-mono text-xs break-all bg-white p-2 rounded border border-slate-200 text-slate-600 select-all">
            {normalizedUrl}
          </div>
        </div>
      )}

      {warnings && warnings.length > 0 && (
        <div className="mt-2 pt-2 border-t border-slate-200 space-y-1">
          <div className="text-xs font-semibold text-amber-700">Normalization notes:</div>
          <ul className="list-disc pl-4 text-xs text-amber-800 space-y-0.5">
            {warnings.map((w, idx) => (
              <li key={idx}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export function FindingsList({ findings }: { findings: string[] }) {
  return (
    <div className="bg-white rounded-xl border p-4">
      <h3 className="font-semibold mb-2">Technical observations</h3>
      <ul className="list-disc pl-5 space-y-1 text-sm">
        {findings.map((f, i) => <li key={i}>{f}</li>)}
      </ul>
    </div>
  );
}

export function EvidencePanel({ evidence }: { evidence: import('../types').Evidence[] }) {
  const color = (s: string) =>
    s === 'HIGH' ? 'border-red-300 bg-red-50' :
    s === 'MEDIUM' ? 'border-amber-300 bg-amber-50' :
    s === 'LOW' ? 'border-emerald-200 bg-emerald-50' : 'border-slate-200 bg-slate-50';
  return (
    <div className="bg-white rounded-xl border p-4">
      <h3 className="font-semibold mb-2">Evidence breakdown ({evidence.length})</h3>
      <div className="space-y-2">
        {evidence.map((e) => (
          <details key={e.id} className={`border rounded-lg p-3 text-sm ${color(e.severity)}`}>
            <summary className="cursor-pointer font-medium">
              [{e.severity}] {e.title}
              <span className="ml-2 text-xs text-slate-500">{e.category} · {e.source ?? 'local'}</span>
            </summary>
            <p className="mt-1 text-slate-700">{e.description}</p>
            {e.confidence != null && <p className="text-xs text-slate-500 mt-1">Confidence factor: {e.confidence}</p>}
          </details>
        ))}
      </div>
    </div>
  );
}

export function RecommendationCard({ items }: { items: string[] }) {
  return (
    <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
      <h3 className="font-semibold mb-2">Recommended security steps</h3>
      <ul className="list-disc pl-5 space-y-1 text-sm text-blue-950">
        {items.map((r, i) => <li key={i}>{r}</li>)}
      </ul>
    </div>
  );
}

export function ProviderStatus({
  status,
  results,
}: {
  status: Record<string, string>;
  results?: ProviderCheckDetail[];
}) {
  const entries = Object.entries(status);
  if (!entries.length) return <p className="text-sm text-slate-500">No live provider checks for this input.</p>;

  return (
    <div className="bg-white rounded-xl border p-4">
      <h3 className="font-semibold mb-2">Threat-intelligence status</h3>
      <div className="flex flex-wrap gap-2 mb-3">
        {entries.map(([k, v]) => {
          const detailObj = results?.find((r) => r.provider === k);
          return (
            <div
              key={k}
              className={`px-3 py-1.5 rounded text-xs border ${
                v === 'match'
                  ? 'bg-red-100 border-red-300 text-red-900 font-semibold'
                  : v === 'no_match'
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                  : 'bg-slate-100 border-slate-300 text-slate-700'
              }`}
            >
              <div><b>{k}</b>: {v}</div>
              {detailObj?.detail && <div className="text-[11px] opacity-80 mt-0.5">{detailObj.detail}</div>}
              {detailObj?.checkedAt && <div className="text-[10px] opacity-60 mt-0.5">{detailObj.checkedAt.split('T')[0]}</div>}
            </div>
          );
        })}
      </div>
      <p className="text-xs text-slate-500">
        “no_match” indicates the provider has no current threat record for this link. This is <b>not</b> proof of safety.
        “unavailable” indicates the provider could not be reached, and local evidence is used instead.
      </p>
    </div>
  );
}

export function LimitationsPanel({ items }: { items: string[] }) {
  return (
    <div className="bg-slate-100 border border-slate-200 rounded-xl p-4">
      <h3 className="font-semibold mb-2">Limitations & unknowns</h3>
      <ul className="list-disc pl-5 space-y-1 text-sm text-slate-700">
        {items.map((l, i) => <li key={i}>{l}</li>)}
      </ul>
    </div>
  );
}
