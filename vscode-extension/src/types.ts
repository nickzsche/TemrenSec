export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type Confidence = "HIGH" | "MEDIUM" | "LOW";

export interface Finding {
  scanner: string;
  severity: Severity;
  title: string;
  url: string;
  description: string;
  payload: string;
  evidence: string;
  confidence: Confidence;
  cvss_score: number;
  timestamp: string;
  parameter: string;
  owasp_category: string;
  request: string;
  response: string;
}

export interface ScanResult {
  target: string;
  timestamp: string;
  total_findings: number;
  summary: Record<string, number>;
  findings: Finding[];
}

export interface ScanOptions {
  depth: number;
  crawl: boolean;
  format: string;
  silent: boolean;
}
