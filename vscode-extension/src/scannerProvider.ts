import * as vscode from "vscode";
import type { Finding, Severity } from "./types";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const SEVERITY_ICONS: Record<Severity, vscode.ThemeIcon> = {
  CRITICAL: new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground")),
  HIGH: new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground")),
  MEDIUM: new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground")),
  LOW: new vscode.ThemeIcon("lightbulb", new vscode.ThemeColor("editorGutter.foldingControlForeground")),
  INFO: new vscode.ThemeIcon("circle-outline"),
};

const SEVERITY_LABELS: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Info",
};

type TreeNode =
  | { type: "severity"; severity: Severity; count: number }
  | { type: "finding"; finding: Finding };

export class VulnerabilityProvider
  implements vscode.TreeDataProvider<TreeNode>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<
    TreeNode | undefined | null
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: Finding[] = [];

  setFindings(findings: Finding[]): void {
    this.findings = findings;
    this._onDidChangeTreeData.fire(undefined);
  }

  clear(): void {
    this.findings = [];
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    if (element.type === "severity") {
      const item = new vscode.TreeItem(
        `${SEVERITY_LABELS[element.severity]} (${element.count})`,
        vscode.TreeItemCollapsibleState.Expanded
      );
      item.iconPath = SEVERITY_ICONS[element.severity];
      item.contextValue = "severity-group";
      item.description = `${element.count} finding${element.count !== 1 ? "s" : ""}`;
      return item;
    }

    const f = element.finding;
    const item = new vscode.TreeItem(
      f.title,
      vscode.TreeItemCollapsibleState.None
    );
    item.iconPath = SEVERITY_ICONS[f.severity];
    item.description = f.scanner;
    item.tooltip = `${f.title}\nScanner: ${f.scanner}\nURL: ${f.url}\nCVSS: ${f.cvss_score}`;
    item.contextValue = "finding";
    item.command = {
      command: "temren.openDetail",
      title: "Open Detail",
      arguments: [f],
    };
    return item;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    if (!element) {
      // Root: severity groups
      const grouped = this.groupBySeverity();
      const nodes: TreeNode[] = [];
      for (const sev of SEVERITY_ORDER) {
        const items = grouped[sev];
        if (items && items.length > 0) {
          nodes.push({ type: "severity", severity: sev, count: items.length });
        }
      }
      return nodes;
    }

    if (element.type === "severity") {
      const grouped = this.groupBySeverity();
      return (grouped[element.severity] || []).map(
        (finding): TreeNode => ({ type: "finding", finding })
      );
    }

    return [];
  }

  private groupBySeverity(): Record<string, Finding[]> {
    const groups: Record<string, Finding[]> = {};
    for (const sev of SEVERITY_ORDER) {
      groups[sev] = [];
    }
    for (const f of this.findings) {
      const sev = f.severity.toUpperCase() as Severity;
      if (!groups[sev]) {
        groups[sev] = [];
      }
      groups[sev].push(f);
    }
    return groups;
  }
}
