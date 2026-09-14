declare module "child_process" {
  interface ChildProcess {
    stdout: { on(event: string, cb: (data: Buffer) => void): void } | null;
    stderr: { on(event: string, cb: (data: Buffer) => void): void } | null;
    on(event: "close", cb: (code: number | null) => void): void;
    on(event: "error", cb: (err: Error) => void): void;
    kill(): void;
  }
  function spawn(
    command: string,
    args: readonly string[],
    options?: { env?: Record<string, string | undefined> }
  ): ChildProcess;
}

declare interface Buffer {
  toString(encoding?: string): string;
}

declare var process: {
  env: Record<string, string | undefined>;
};
