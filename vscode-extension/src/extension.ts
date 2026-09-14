import * as vscode from "vscode";
import { ScanRunner } from "./scanRunner";
import { VulnerabilityProvider } from "./scannerProvider";
import { ScanPanel } from "./webview/scanPanel";
import type { Finding, ScanResult } from "./types";

let scanRunner: ScanRunner;
let scannerProvider: VulnerabilityProvider;
let statusBarItem: vscode.StatusBarItem;
let latestResult: ScanResult | undefined;

export function activate(context: vscode.ExtensionContext): void {
  scanRunner = new ScanRunner();
  scannerProvider = new VulnerabilityProvider();

  // Status bar item
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.text = "$(shield) Temren";
  statusBarItem.tooltip = "Temren OWASP Scanner - Idle";
  statusBarItem.command = "temren.showResults";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Wire up progress events
  scanRunner.on("progress", (p: { stage: string }) => {
    statusBarItem.text = `$(loading~spin) Temren: ${p.stage}`;
    statusBarItem.tooltip = `Temren OWASP Scanner - ${p.stage}`;
  });

  scanRunner.on("start", () => {
    statusBarItem.text = "$(loading~spin) Temren: Scanning...";
    statusBarItem.tooltip = "Temren OWASP Scanner - Scanning in progress";
  });

  // Register tree view
  const treeView = vscode.window.createTreeView("temren-vulnerabilities", {
    treeDataProvider: scannerProvider,
    showCollapseAll: true,
  });
  context.subscriptions.push(treeView);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("temren.scan", () => cmdScan()),
    vscode.commands.registerCommand("temren.scanQuick", () => cmdScanQuick()),
    vscode.commands.registerCommand("temren.scanFull", () => cmdScanFull()),
    vscode.commands.registerCommand("temren.showResults", () => cmdShowResults()),
    vscode.commands.registerCommand("temren.clearResults", () => cmdClearResults()),
    vscode.commands.registerCommand("temren.openDetail", (finding: Finding) => cmdOpenDetail(finding))
  );
}

export function deactivate(): void {
  statusBarItem.dispose();
  ScanPanel.currentPanel?.dispose();
}

async function cmdScan(): Promise<void> {
  const config = vscode.workspace.getConfiguration("temren");
  const defaultTarget = config.get<string>("defaultTarget") || "";

  const target = await vscode.window.showInputBox({
    prompt: "Enter target URL to scan",
    value: defaultTarget,
    placeHolder: "https://example.com",
    validateInput: (value: string) => {
      if (!value.trim()) {
        return "Target URL is required";
      }
      try {
        const url = new URL(value);
        if (!url.protocol.startsWith("http")) {
          return "URL must start with http:// or https://";
        }
      } catch {
        return "Enter a valid URL (e.g., https://example.com)";
      }
      return undefined;
    },
  });

  if (!target) {
    return;
  }

  const depthStr = await vscode.window.showQuickPick(["1", "2", "3", "4", "5"], {
    placeHolder: "Select scan depth",
  });

  const depth = depthStr ? parseInt(depthStr, 10) : 2;

  await executeScan(() =>
    scanRunner.runScan(target, {
      depth,
      crawl: depth > 1,
      format: "json",
      silent: true,
    })
  );
}

async function cmdScanQuick(): Promise<void> {
  const target = await promptForTarget();
  if (!target) {
    return;
  }
  await executeScan(() => scanRunner.runQuickScan(target));
}

async function cmdScanFull(): Promise<void> {
  const target = await promptForTarget();
  if (!target) {
    return;
  }
  await executeScan(() => scanRunner.runFullScan(target));
}

function cmdShowResults(): void {
  if (latestResult) {
    ScanPanel.createOrShow(latestResult);
  } else {
    vscode.window.showInformationMessage("No scan results available. Run a scan first.");
  }
}

function cmdClearResults(): void {
  latestResult = undefined;
  scannerProvider.clear();
  statusBarItem.text = "$(shield) Temren";
  statusBarItem.tooltip = "Temren OWASP Scanner - Idle";
  ScanPanel.currentPanel?.dispose();
  vscode.window.showInformationMessage("Temren results cleared.");
}

function cmdOpenDetail(finding: Finding): void {
  if (!latestResult) {
    vscode.window.showWarningMessage("No scan results available.");
    return;
  }

  const panel = ScanPanel.createOrShow(latestResult);
  // The webview doesn't support programmatic detail selection via this path,
  // so we show the detail in a VS Code information message as fallback.
  const detail = [
    `[${finding.severity}] ${finding.title}`,
    `Scanner: ${finding.scanner}`,
    `URL: ${finding.url}`,
    finding.description ? `Description: ${finding.description}` : null,
    finding.payload ? `Payload: ${finding.payload}` : null,
    finding.evidence ? `Evidence: ${finding.evidence}` : null,
    finding.cvss_score ? `CVSS: ${finding.cvss_score}` : null,
  ]
    .filter(Boolean)
    .join("\n");

  vscode.window.showInformationMessage(detail, { modal: true }, "OK");
}

async function promptForTarget(): Promise<string | undefined> {
  const config = vscode.workspace.getConfiguration("temren");
  const defaultTarget = config.get<string>("defaultTarget") || "";

  const target = await vscode.window.showInputBox({
    prompt: "Enter target URL to scan",
    value: defaultTarget,
    placeHolder: "https://example.com",
    validateInput: (value: string) => {
      if (!value.trim()) {
        return "Target URL is required";
      }
      try {
        const url = new URL(value);
        if (!url.protocol.startsWith("http")) {
          return "URL must start with http:// or https://";
        }
      } catch {
        return "Enter a valid URL (e.g., https://example.com)";
      }
      return undefined;
    },
  });

  return target;
}

async function executeScan(
  scanFn: () => Promise<ScanResult>
): Promise<void> {
  try {
    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Temren Security Scan",
        cancellable: true,
      },
      async (progress, token) => {
        token.onCancellationRequested(() => {
          // The child process will end naturally; we just note cancellation.
          vscode.window.showInformationMessage("Temren scan cancelled.");
        });

        progress.report({ message: "Running security scan..." });

        const scanResult = await scanFn();
        return scanResult;
      }
    );

    latestResult = result;
    scannerProvider.setFindings(result.findings);

    const criticalCount = result.summary["CRITICAL"] ?? 0;
    const highCount = result.summary["HIGH"] ?? 0;
    const totalCount = result.total_findings;

    statusBarItem.text = `$(shield) Temren: ${totalCount} finding${totalCount !== 1 ? "s" : ""}`;
    statusBarItem.tooltip = `Temren Scan Complete\nCritical: ${criticalCount}, High: ${highCount}, Total: ${totalCount}`;

    if (totalCount > 0) {
      vscode.window.showWarningMessage(
        `Temren found ${totalCount} vulnerability${totalCount !== 1 ? "ies" : "y"} (${criticalCount} critical, ${highCount} high).`,
        "View Results"
      ).then((choice) => {
        if (choice === "View Results") {
          ScanPanel.createOrShow(result);
        }
      });
    } else {
      vscode.window.showInformationMessage("Temren scan complete. No vulnerabilities found.");
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    statusBarItem.text = "$(shield) Temren: Error";
    statusBarItem.tooltip = `Temren Scan Failed: ${message}`;
    vscode.window.showErrorMessage(`Temren scan failed: ${message}`);
  }
}
