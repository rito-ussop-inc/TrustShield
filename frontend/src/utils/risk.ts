import type { RiskLevel } from '../types';

export function riskColor(level: RiskLevel): string {
  switch (level) {
    case 'LOW': return 'bg-emerald-100 text-emerald-800 border-emerald-300';
    case 'MEDIUM': return 'bg-amber-100 text-amber-800 border-amber-300';
    case 'HIGH': return 'bg-orange-100 text-orange-800 border-orange-400';
    case 'CRITICAL': return 'bg-red-100 text-red-800 border-red-400';
    default: return 'bg-slate-100 text-slate-700 border-slate-300';
  }
}

export function riskLabel(level: RiskLevel): string {
  switch (level) {
    case 'LOW': return 'Low observed risk';
    case 'MEDIUM': return 'Potentially suspicious';
    case 'HIGH': return 'High risk based on detected signals';
    case 'CRITICAL': return 'Critical risk — do not trust';
    default: return 'Unknown — not confirmed safe';
  }
}
