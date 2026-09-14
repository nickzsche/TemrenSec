import * as vscode from "vscode";
import type { Finding, ScanResult, Severity } from "../types";

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "#e74c3c",
  HIGH: "#e67e22",
  MEDIUM: "#f39c12",
  LOW: "#3498db",
  INFO: "#95a5a6",
};

export class ScanPanel {
  public static currentPanel: ScanPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  private constructor(panel: vscode.WebviewPanel, private result: ScanResult) {
    this.panel = panel;
    this.update(result);

    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  public static createOrShow(result: ScanResult): ScanPanel {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined;

    if (ScanPanel.currentPanel) {
      ScanPanel.currentPanel.panel.reveal(column);
      ScanPanel.currentPanel.update(result);
      return ScanPanel.currentPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      "temrenScanResults",
      `Temren: ${result.target}`,
      column || vscode.ViewColumn.One,
      { enableScripts: true }
    );

    ScanPanel.currentPanel = new ScanPanel(panel, result);
    return ScanPanel.currentPanel;
  }

  public update(result: ScanResult): void {
    this.result = result;
    this.panel.title = `Temren: ${result.target}`;
    this.panel.webview.html = this.getHtml(result);
  }

  public dispose(): void {
    ScanPanel.currentPanel = undefined;
    this.panel.dispose();
    for (const d of this.disposables) {
      d.dispose();
    }
    this.disposables = [];
  }

  private getHtml(result: ScanResult): string {
    const sortedFindings = [...result.findings].sort(
      (a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
    );

    const summaryRow = this.buildSummaryRow(result.summary, result.total_findings);
    const tableRows = sortedFindings
      .map((f, i) => this.buildFindingRow(f, i))
      .join("");

    return /* html */ `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Temren Scan Results</title>
  <style>
    :root {
      --bg: var(--vscode-editor-background);
      --fg: var(--vscode-editor-foreground);
      --border: var(--vscode-panel-border);
      --font: var(--vscode-editor-font-family);
    }
    body {
      font-family: var(--font);
      color: var(--fg);
      background: var(--bg);
      padding: 16px;
      margin: 0;
    }
    h1 { font-size: 1.4em; margin-bottom: 4px; }
    .meta { color: var(--vscode-descriptionForeground); margin-bottom: 16px; font-size: 0.9em; }
    .summary {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .summary-chip {
      padding: 6px 14px;
      border-radius: 4px;
      color: white;
      font-weight: bold;
      font-size: 0.85em;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 24px;
    }
    th, td {
      text-align: left;
      padding: 8px 12px;
      border-bottom: 1px solid var(--border);
    }
    th {
      font-weight: 600;
      cursor: pointer;
      user-select: none;
    }
    th:hover { opacity: 0.8; }
    tr:hover { background: var(--vscode-list-hoverBackground); }
    .sev-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 3px;
      color: white;
      font-size: 0.8em;
      font-weight: bold;
    }
    .detail-panel {
      display: none;
      background: var(--vscode-textBlockQuote-background);
      border-left: 3px solid var(--vscode-focusBorder);
      padding: 12px 16px;
      margin: 8px 0 16px 0;
      border-radius: 0 4px 4px 0;
    }
    .detail-panel.active { display: block; }
    .detail-panel h3 { margin: 0 0 8px 0; }
    .detail-field { margin: 4px 0; font-size: 0.9em; }
    .detail-field strong { display: inline-block; min-width: 120px; }
    .detail-field pre {
      background: var(--vscode-textCodeBlock-background);
      padding: 8px;
      border-radius: 3px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      margin: 4px 0;
      font-size: 0.85em;
    }
  </style>
</head>
<body>
  <h1>Temren Scan Results</h1>
  <div class="meta">
    Target: <strong>${escapeHtml(result.target)}</strong> &mdash;
    ${result.total_findings} finding${result.total_findings !== 1 ? "s" : ""} &mdash;
    ${escapeHtml(result.timestamp)}
  </div>

  <div class="summary">${summaryRow}</div>

  <table>
    <thead>
      <tr>
        <th data-sort="severity">Severity</th>
        <th data-sort="title">Title</th>
        <th data-sort="scanner">Scanner</th>
        <th data-sort="url">URL</th>
        <th data-sort="cvss">CVSS</th>
      </tr>
    </thead>
    <tbody id="findings-body">${tableRows}</tbody>
  </table>

  <div id="detail-panel" class="detail-panel"></div>

  <script>
    const findings = ${JSON.stringify(sortedFindings)};

    function toggleDetail(index) {
      const panel = document.getElementById('detail-panel');
      const f = findings[index];
      if (!f) return;

      if (panel.classList.contains('active') && panel.dataset.index === String(index)) {
        panel.classList.remove('active');
        panel.dataset.index = '';
        return;
      }

      const colors = ${JSON.stringify(SEVERITY_COLORS)};
      const sevColor = colors[f.severity] || '#95a5a6';

      panel.innerHTML = \`
        <h3>\${escapeHtml(f.title)}</h3>
        <div class="detail-field"><strong>Severity:</strong> <span class="sev-badge" style="background:\${sevColor}">\${escapeHtml(f.severity)}</span></div>
        <div class="detail-field"><strong>Scanner:</strong> \${escapeHtml(f.scanner)}</div>
        <div class="detail-field"><strong>URL:</strong> \${escapeHtml(f.url)}</div>
        <div class="detail-field"><strong>Confidence:</strong> \${escapeHtml(f.confidence)}</div>
        <div class="detail-field"><strong>CVSS Score:</strong> \${f.cvss_score}</div>
        <div class="detail-field"><strong>OWASP Category:</strong> \${escapeHtml(f.owasp_category)}</div>
        \${f.description ? \`<div class="detail-field"><strong>Description:</strong><pre>\${escapeHtml(f.description)}</pre></div>\` : ''}
        \${f.payload ? \`<div class="detail-field"><strong>Payload:</strong><pre>\${escapeHtml(f.payload)}</pre></div>\` : ''}
        \${f.evidence ? \`<div class="detail-field"><strong>Evidence:</strong><pre>\${escapeHtml(f.evidence)}</pre></div>\` : ''}
        \${f.remediation ? \`<div class="detail-field"><strong>Remediation:</strong><pre>\${escapeHtml(f.remediation)}</pre></div>\` : ''}
      \`;
      panel.classList.add('active');
      panel.dataset.index = String(index);
    }

    function escapeHtml(s) {
      if (!s) return '';
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
  </script>
</body>
</html>`;
  }

  private buildSummaryRow(
    summary: Record<string, number>,
    total: number
  ): string {
    let html = `<span class="summary-chip" style="background:var(--vscode-button-background)">Total: ${total}</span>`;
    for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[]) {
      const count = summary[sev] ?? 0;
      if (count > 0) {
        html += `<span class="summary-chip" style="background:${SEVERITY_COLORS[sev]}">${sev}: ${count}</span>`;
      }
    }
    return html;
  }

  private buildFindingRow(f: Finding, index: number): string {
    const color = SEVERITY_COLORS[f.severity] || "#95a5a6";
    return /* html */ `
    <tr onclick="toggleDetail(${index})">
      <td><span class="sev-badge" style="background:${color}">${escapeHtml(f.severity)}</span></td>
      <td>${escapeHtml(f.title)}</td>
      <td>${escapeHtml(f.scanner)}</td>
      <td title="${escapeHtml(f.url)}">${escapeHtml(truncate(f.url, 50))}</td>
      <td>${f.cvss_score > 0 ? f.cvss_score.toFixed(1) : "-"}</td>
    </tr>`;
  }
}

function escapeHtml(s: string): string {
  if (!s) {
    return "";
  }
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function truncate(s: string, maxLen: number): string {
  if (!s || s.length <= maxLen) {
    return s;
  }
  return s.substring(0, maxLen) + "...";
}
