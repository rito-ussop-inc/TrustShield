import type { RiskLevel } from '../types';

/** Product display labels (PRD §24). Never render backend levels as "safe". */
export function riskDisplayLabel(level: RiskLevel): string {
  switch (level) {
    case 'LOW': return 'LOW OBSERVED RISK';
    case 'MEDIUM': return 'MODERATE RISK';
    case 'HIGH': return 'HIGH RISK';
    case 'CRITICAL': return 'CRITICAL RISK';
    default: return 'INSUFFICIENT EVIDENCE';
  }
}

export function riskColor(level: RiskLevel): string {
  switch (level) {
    case 'LOW': return 'bg-emerald-500/10 text-emerald-300 border-emerald-400/30';
    case 'MEDIUM': return 'bg-amber-500/10 text-amber-300 border-amber-400/30';
    case 'HIGH': return 'bg-rose-500/10 text-rose-300 border-rose-400/40';
    case 'CRITICAL': return 'bg-red-500/15 text-red-300 border-red-500/50';
    default: return 'bg-slate-500/10 text-slate-300 border-slate-400/30';
  }
}

export function riskDot(level: RiskLevel): string {
  switch (level) {
    case 'LOW': return 'bg-emerald-400';
    case 'MEDIUM': return 'bg-amber-400';
    case 'HIGH': return 'bg-rose-400';
    case 'CRITICAL': return 'bg-red-500';
    default: return 'bg-slate-400';
  }
}

/** Legacy human-readable subtitle kept for compact badges. */
export function riskLabel(level: RiskLevel): string {
  switch (level) {
    case 'LOW': return 'Low observed risk — not a safety guarantee';
    case 'MEDIUM': return 'Potentially suspicious';
    case 'HIGH': return 'High risk based on detected signals';
    case 'CRITICAL': return 'Critical risk — do not trust';
    default: return 'Unknown — not confirmed safe';
  }
}
