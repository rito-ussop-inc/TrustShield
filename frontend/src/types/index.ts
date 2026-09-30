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
}
