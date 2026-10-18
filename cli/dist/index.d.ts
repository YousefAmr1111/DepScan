export type OutputWriter = (line: string) => void;
export declare function usage(): string;
/** Runs the CLI and returns the process exit code (0 = success, 1 = usage error). */
export declare function runCli(argv: readonly string[], write?: OutputWriter): number;
//# sourceMappingURL=index.d.ts.map