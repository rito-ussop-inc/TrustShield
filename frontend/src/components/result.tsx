import type { RiskLevel, ProviderCheckDetail, PlainLanguageSummary } from '../types';
import { riskColor, riskDisplayLabel, riskDot, riskLabel } from '../utils/risk';

export function RiskBadge({ level, compact = false }: { level: RiskLevel; compact?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wider border ${riskColor(level)}`}>
      <span aria-hidden="true" className={`w-1.5 h-1.5 rounded-full ${riskDot(level)}`} />
      {riskDisplayLabel(level)}
      {!compact && <span className="font-sans font-normal normal-case tracking-normal opacity-80">· {riskLabel(level)}</span>}
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
  const frame =
    level === 'CRITICAL' || level === 'HIGH'
      ? 'border-red-500/40 bg-red-500/[0.07]'
      : level === 'MEDIUM'
      ? 'border-amber-400/30 bg-amber-400/[0.06]'
      : level === 'LOW'
      ? 'border-emerald-400/25 bg-emerald-400/[0.05]'
      : 'border-white/10 bg-white/[0.03]';
  const badge =
    level === 'CRITICAL' ? 'bg-red-500 text-white'
      : level === 'HIGH' ? 'bg-rose-500 text-white'
      : level === 'MEDIUM' ? 'bg-amber-400 text-ink-950'
      : level === 'LOW' ? 'bg-emerald-400 text-ink-950'
      : 'bg-slate-400 text-ink-950';
  return (
    <div className={`rounded-xl border p-5 space-y-3 ${frame}`}>
      <div className="flex items-center justify-between flex-wrap gap-2">
        <span className={`text-[11px] font-mono font-bold tracking-widest px-2.5 py-1 rounded ${badge}`}>
          {summary.verdictBadge || riskDisplayLabel(level)}
        </span>
        <span className="text-[11px] font-mono tracking-widest text-mist-500">PLAIN-LANGUAGE SUMMARY</span>
      </div>
      <h2 className="text-xl font-bold leading-snug">{summary.headline}</h2>
      <p className="text-sm leading-relaxed text-mist-300">{summary.explanation}</p>
      {summary.targetIdentity && (
        <p className="text-xs text-mist-300">Real destination: <span className="font-mono text-mist-100">{summary.targetIdentity}</span></p>
      )}
      {summary.securityNotice && (
        <div className="rounded-lg border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-xs text-amber-200">
          {summary.securityNotice}
        </div>
      )}
      <div className="rounded-lg border border-white/10 bg-ink-950/60 px-3 py-2.5">
        <div className="text-[11px] font-mono tracking-widest text-mist-500">WHAT YOU SHOULD DO</div>
        <div className="mt-1 text-sm font-medium">{summary.actionAdvice}</div>
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
    level === 'CRITICAL' ? 'bg-red-500' :
    level === 'HIGH' ? 'bg-rose-400' :
    level === 'MEDIUM' ? 'bg-amber-400' :
    level === 'LOW' ? 'bg-emerald-400' : 'bg-slate-400';
  return (
    <div>
      <div className="flex items-baseline gap-2">
        <span className="text-4xl font-extrabold tabular-nums">{score ?? '—'}</span>
        <span className="text-sm text-mist-500">/ 100</span>
      </div>
      <p className="mt-0.5 text-[11px] font-mono tracking-widest text-mist-500">RISK SCORE</p>
      <div className="mt-2 h-2 w-full bg-white/10 rounded-full overflow-hidden" role="img" aria-label={`Risk score ${score ?? 'unknown'} out of 100`}>
        <div className={`h-full ${bar} transition-all`} style={{ width: `${v}%` }} />
      </div>
      <p className="mt-2 text-xs text-mist-500">
        Evidence score ({scoringVersion ?? 'calibrated'}). High scores indicate observed risk; a low score does not guarantee safety.
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
    <div className="surface-raised rounded-xl p-4 space-y-2.5 text-sm">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <span className="font-semibold text-mist-300 text-xs font-mono tracking-widest">TARGET DETAILS</span>
        {modelVersion && (
          <span className="text-[11px] px-2 py-0.5 rounded border border-white/10 bg-white/5 text-mist-300 font-mono">
            Model: {modelVersion} ({modelStatus ?? 'unknown'})
          </span>
        )}
      </div>
      <div className="space-y-1">
        <div className="text-[11px] text-mist-500">Submitted URL</div>
        <div className="font-mono text-xs break-all bg-ink-950 p-2 rounded border border-white/10 text-mist-100 select-all">
          {rawUrl || normalizedUrl}
        </div>
      </div>
      {normalizedUrl && rawUrl && normalizedUrl !== rawUrl && (
        <div className="space-y-1">
          <div className="text-[11px] text-mist-500">Normalized canonical form</div>
          <div className="font-mono text-xs break-all bg-ink-950 p-2 rounded border border-white/10 text-mist-300 select-all">
            {normalizedUrl}
          </div>
        </div>
      )}
      {warnings && warnings.length > 0 && (
        <div className="pt-2 border-t border-white/10 space-y-1">
          <div className="text-[11px] font-semibold text-amber-300">Normalization notes</div>
          <ul className="list-disc pl-4 text-xs text-amber-200/90 space-y-0.5">
            {warnings.map((w, idx) => <li key={idx}>{w}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

export function FindingsList({ findings }: { findings: string[] }) {
  return (
    <div className="surface rounded-xl p-4">
      <h3 className="font-mono text-xs tracking-widest text-mist-500 mb-2">FINDINGS</h3>
      <ul className="list-disc pl-5 space-y-1 text-sm text-mist-100">
        {findings.map((f, i) => <li key={i}>{f}</li>)}
      </ul>
    </div>
  );
}

export function EvidencePanel({ evidence }: { evidence: import('../types').Evidence[] }) {
  const color = (s: string) =>
    s === 'HIGH' ? 'border-red-500/30 bg-red-500/[0.05]' :
    s === 'MEDIUM' ? 'border-amber-400/25 bg-amber-400/[0.05]' :
    s === 'LOW' ? 'border-emerald-400/20 bg-emerald-400/[0.04]' : 'border-white/10 bg-white/[0.02]';
  return (
    <div className="surface rounded-xl p-4">
      <h3 className="font-mono text-xs tracking-widest text-mist-500 mb-1">WHY THIS RESULT?</h3>
      <p className="text-xs text-mist-500 mb-3">Evidence breakdown ({evidence.length})</p>
      <div className="space-y-2">
        {evidence.map((e) => (
          <details key={e.id} className={`border rounded-lg p-3 text-sm ${color(e.severity)}`}>
            <summary className="cursor-pointer font-medium">
              [{e.severity}] {e.title}
              <span className="ml-2 text-[11px] font-mono text-mist-500">{e.category} · {e.source ?? 'local'}</span>
            </summary>
            <p className="mt-1 text-mist-300">{e.description}</p>
            {e.confidence != null && <p className="text-[11px] text-mist-500 mt-1">Confidence factor: {e.confidence}</p>}
          </details>
        ))}
      </div>
    </div>
  );
}

export function RecommendationCard({ items }: { items: string[] }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
      <h3 className="font-mono text-xs tracking-widest text-mist-500 mb-2">RECOMMENDED ACTION</h3>
      <ul className="list-disc pl-5 space-y-1 text-sm">
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
  if (!entries.length) return <p className="text-sm text-mist-500">No live provider checks for this input.</p>;
  return (
    <div className="surface rounded-xl p-4">
      <h3 className="font-mono text-xs tracking-widest text-mist-500 mb-2">THREAT-INTELLIGENCE STATUS</h3>
      <div className="flex flex-wrap gap-2 mb-3">
        {entries.map(([k, v]) => {
          const detailObj = results?.find((r) => r.provider === k);
          return (
            <div
              key={k}
              className={`px-3 py-1.5 rounded text-xs border font-mono ${
                v === 'match'
                  ? 'bg-red-500/15 border-red-500/40 text-red-200 font-bold'
                  : v === 'no_match'
                  ? 'bg-emerald-400/10 border-emerald-400/25 text-emerald-200'
                  : 'bg-white/[0.03] border-white/10 text-mist-300'
              }`}
            >
              <div><b>{k}</b>: {v === 'no_match' ? 'no match observed' : v}</div>
              {detailObj?.detail && <div className="text-[11px] opacity-80 mt-0.5 font-sans">{detailObj.detail}</div>}
              {detailObj?.checkedAt && <div className="text-[10px] opacity-60 mt-0.5">{detailObj.checkedAt.split('T')[0]}</div>}
            </div>
          );
        })}
      </div>
      <p className="text-xs text-mist-500">
        “No match observed” means the provider has no current threat record for this link — <b>not</b> proof of safety.
        “Unavailable” means the provider could not be reached; local evidence was used instead.
      </p>
    </div>
  );
}

export function LimitationsPanel({ items }: { items: string[] }) {
  return (
    <div className="rounded-xl border border-white/10 bg-ink-950/60 p-4">
      <h3 className="font-mono text-xs tracking-widest text-mist-500 mb-2">ABOUT THIS ASSESSMENT</h3>
      <ul className="list-disc pl-5 space-y-1 text-sm text-mist-300">
        {items.map((l, i) => <li key={i}>{l}</li>)}
      </ul>
    </div>
  );
}
