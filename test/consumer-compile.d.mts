export type CompileResult = {
  status: number | null;
  signal: NodeJS.Signals | string | null;
  error?: unknown;
  stdout?: string;
  stderr?: string;
};

export type CompileEvaluation = { ok: boolean; reasons: string[]; errors: string[] };

export declare function parseDiagnostics(output: string | undefined): string[];
export declare function evaluateCompile(result: CompileResult): CompileEvaluation;
