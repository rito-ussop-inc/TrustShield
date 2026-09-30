export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN';

export interface Evidence {
  id: string;
  category: string;
  title: string;
  description: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH';
  source?: string;
  confidence?: number | null;
}

export interface ProviderCheckDetail {
  provider: string;
  status: string;
  matched: boolean;
  category?: string | null;
  detail?: string | null;
  checkedAt?: string | null;
}

export interface PlainLanguageSummary {
  headline: string;
  explanation: string;
  actionAdvice: string;
  verdictBadge: string;
  targetIdentity?: string | null;
  securityNotice?: string | null;
}

export interface AnalysisResult {
  analysisId: string;
  inputType: 'URL' | 'QR' | 'MESSAGE' | 'DOCUMENT';
  riskScore?: number | null;
  riskLevel: RiskLevel;
  confidence?: number | null;
  findings: string[];
  evidence: Evidence[];
  recommendation: string[];
  limitations: string[];
  providerStatus: Record<string, string>;
  decodedPayload?: string | null;
  payloadType?: string | null;
  fileSha256?: string | null;

  // URL transparency attributes
  rawUrl?: string | null;
  normalizedUrl?: string | null;
  normalizationWarnings?: string[];
  modelStatus?: string | null;
  modelVersion?: string | null;
  scoringVersion?: string | null;
  providerResults?: ProviderCheckDetail[];

  // Layman / non-technical summary
  plainSummary?: PlainLanguageSummary | null;
}

export interface HistoryItem {
  analysisId: string;
  inputType: 'URL' | 'QR' | 'MESSAGE' | 'DOCUMENT';
  riskLevel: RiskLevel;
  riskScore: number | null;
  createdAt: string;
  inputSummary?: string | null;
}
