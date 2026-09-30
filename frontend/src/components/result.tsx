import type { RiskLevel } from '../types';
import { riskColor, riskLabel } from '../utils/risk';

export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold border ${riskColor(level)}`}>
      {level} · {riskLabel(level)}
    </span>
  );
}

export function RiskScore({ score, level }: { score?: number | null; level: RiskLevel }) {
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
      <p className="mt-1 text-xs text-slate-500">Weighted evidence score — calibrated initial values, not a scientific certainty.</p>
    </div>
  );
}

export function FindingsList({ findings }: { findings: string[] }) {
  return (
    <div className="bg-white rounded-xl border p-4">
      <h3 className="font-semibold mb-2">Key findings</h3>
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
      <h3 className="font-semibold mb-2">Evidence ({evidence.length})</h3>
      <div className="space-y-2">
        {evidence.map((e) => (
          <details key={e.id} className={`border rounded-lg p-3 text-sm ${color(e.severity)}`}>
            <summary className="cursor-pointer font-medium">
              [{e.severity}] {e.title}
              <span className="ml-2 text-xs text-slate-500">{e.category} · {e.source ?? 'local'}</span>
            </summary>
            <p className="mt-1 text-slate-700">{e.description}</p>
            {e.confidence != null && <p className="text-xs text-slate-500 mt-1">confidence: {e.confidence}</p>}
          </details>
        ))}
      </div>
    </div>
  );
}

export function RecommendationCard({ items }: { items: string[] }) {
  return (
    <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
      <h3 className="font-semibold mb-2">Recommendation</h3>
      <ul className="list-disc pl-5 space-y-1 text-sm">
        {items.map((r, i) => <li key={i}>{r}</li>)}
      </ul>
    </div>
  );
}

export function ProviderStatus({ status }: { status: Record<string, string> }) {
  const entries = Object.entries(status);
  if (!entries.length) return <p className="text-sm text-slate-500">No live provider checks for this input.</p>;
  return (
    <div className="bg-white rounded-xl border p-4">
      <h3 className="font-semibold mb-2">Threat-intelligence status</h3>
      <div className="flex flex-wrap gap-2">
        {entries.map(([k, v]) => (
          <span key={k} className={`px-2 py-1 rounded text-xs border ${v === 'match' ? 'bg-red-100 border-red-300 text-red-800' : v === 'no_match' ? 'bg-emerald-50 border-emerald-200 text-emerald-700' : 'bg-slate-100 border-slate-300 text-slate-600'}`}>
            {k}: {v}
          </span>
        ))}
      </div>
      <p className="text-xs text-slate-500 mt-2">“no_match” is not proof of safety. “unavailable / not_configured” means local signals only.</p>
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
