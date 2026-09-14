import { spawn } from "child_process";
import * as vscode from "vscode";
import { parseScanResult } from "./resultParser";
import type { ScanResult, ScanOptions } from "./types";

export interface ScanProgress {
  stage: string;
  percent: number;
}

type ProgressCallback = (p: ScanProgress) => void;
type VoidCallback = () => void;

export class ScanRunner {
  private running = false;
  private onProgress: ProgressCallback | undefined;
  private onStart: VoidCallback | undefined;

  on(event: "progress", cb: ProgressCallback): void;
  on(event: "start", cb: VoidCallback): void;
  on(event: string, cb: ProgressCallback | VoidCallback): void {
    if (event === "progress") {
      this.onProgress = cb as ProgressCallback;
    } else if (event === "start") {
      this.onStart = cb as VoidCallback;
    }
  }

  isRunning(): boolean {
    return this.running;
  }

  async runScan(target: string, options: ScanOptions): Promise<ScanResult> {
    if (this.running) {
      throw new Error("A scan is already in progress");
    }

    this.running = true;
    this.onStart?.();

    try {
      const config = vscode.workspace.getConfiguration("temren");
      const executable = config.get<string>("executablePath") || "temren";

      const args = [
        "scan",
        "--target", target,
        "--format", "json",
        "--depth", String(options.depth),
        "--silent",
      ];

      if (!options.crawl) {
        args.push("--no-crawl");
      }

      this.onProgress?.({ stage: "Starting scan", percent: 0 });

      return await new Promise<ScanResult>((resolve, reject) => {
        const proc = spawn(executable, args, {
          env: { ...process.env } as Record<string, string | undefined>,
        });

        let stdout = "";
        let stderr = "";

        proc.stdout?.on("data", (data: Buffer) => {
          stdout += data.toString();
          this.onProgress?.({ stage: "Scanning", percent: 50 });
        });

        proc.stderr?.on("data", (data: Buffer) => {
          stderr += data.toString();
        });

        proc.on("close", (code: number | null) => {
          this.running = false;

          if ((code ?? 1) !== 0 && !stdout) {
            reject(
              new Error(
                `temren exited with code ${code}: ${stderr || "No output"}`
              )
            );
            return;
          }

          try {
            const result = parseScanResult(stdout);
            this.onProgress?.({ stage: "Complete", percent: 100 });
            resolve(result);
          } catch (err) {
            reject(
              new Error(
                `Failed to parse scan output: ${err instanceof Error ? err.message : String(err)}`
              )
            );
          }
        });

        proc.on("error", (err: Error) => {
          this.running = false;
          reject(new Error(`Failed to start temren: ${err.message}`));
        });
      });
    } catch (err) {
      this.running = false;
      throw err;
    }
  }

  async runQuickScan(target: string): Promise<ScanResult> {
    return this.runScan(target, {
      depth: 1,
      crawl: false,
      format: "json",
      silent: true,
    });
  }

  async runFullScan(target: string): Promise<ScanResult> {
    return this.runScan(target, {
      depth: 3,
      crawl: true,
      format: "json",
      silent: true,
    });
  }
}
