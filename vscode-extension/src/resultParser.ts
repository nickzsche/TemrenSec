import * as vscode from "vscode";
import type { ScanResult, Severity } from "./types";

export function parseScanResult(jsonStr: string): ScanResult {
  const raw = JSON.parse(jsonStr);

  const findings = (raw.findings || []).map((f: Record<string, unknown>) => ({
    scanner: String(f.Scanner ?? f.scanner ?? "unknown"),
    severity: normalizeSeverity(String(f.Severity ?? f.severity ?? "INFO")),
    title: String(f.Title ?? f.title ?? "Untitled"),
    url: String(f.URL ?? f.url ?? ""),
    description: String(f.Description ?? f.description ?? ""),
    payload: String(f.Payload ?? f.payload ?? ""),
    evidence: String(f.Evidence ?? f.evidence ?? ""),
    confidence: normalizeConfidence(String(f.Confidence ?? f.confidence ?? "MEDIUM")),
    cvss_score: Number(f.CVSSScore ?? f.cvss_score ?? 0),
    timestamp: String(f.Timestamp ?? f.timestamp ?? ""),
    parameter: String(f.Parameter ?? f.parameter ?? ""),
    owasp_category: String(f.OWASPCategory ?? f.owasp_category ?? ""),
    request: String(f.Request ?? f.request ?? ""),
    response: String(f.Response ?? f.response ?? ""),
  }));

  return {
    target: String(raw.target ?? ""),
    timestamp: String(raw.timestamp ?? ""),
    total_findings: Number(raw.total_findings ?? findings.length),
    summary: raw.summary ?? buildSummary(findings),
    findings,
  };
}

export function severityToDiagnosticSeverity(
  sev: string
): vscode.DiagnosticSeverity {
  const normalized = sev.toUpperCase();
  if (normalized === "CRITICAL" || normalized === "HIGH") {
    return vscode.DiagnosticSeverity.Error;
  }
  if (normalized === "MEDIUM") {
    return vscode.DiagnosticSeverity.Warning;
  }
  if (normalized === "LOW") {
    return vscode.DiagnosticSeverity.Information;
  }
  return vscode.DiagnosticSeverity.Hint;
}

function normalizeSeverity(raw: string): Severity {
  const upper = raw.toUpperCase();
  if (
    upper === "CRITICAL" ||
    upper === "HIGH" ||
    upper === "MEDIUM" ||
    upper === "LOW" ||
    upper === "INFO"
  ) {
    return upper as Severity;
  }
  return "INFO";
}

function normalizeConfidence(raw: string): "HIGH" | "MEDIUM" | "LOW" {
  const upper = raw.toUpperCase();
  if (upper === "HIGH" || upper === "MEDIUM" || upper === "LOW") {
    return upper as "HIGH" | "MEDIUM" | "LOW";
  }
  return "MEDIUM";
}

function buildSummary(
  findings: { severity: Severity }[]
): Record<string, number> {
  const summary: Record<string, number> = {};
  for (const f of findings) {
    summary[f.severity] = (summary[f.severity] ?? 0) + 1;
  }
  return summary;
}
