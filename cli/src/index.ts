import { CORE_PACKAGE_NAME, SEVERITIES } from '@depscan/core';

export type OutputWriter = (line: string) => void;

const defaultWriter: OutputWriter = (line) => {
  console.log(line);
};

export function usage(): string {
  return [
    'Usage: depscan <command> [options]',
    '',
    'Commands:',
    '  analyze <dir>   Run the deterministic analysis engine on a project directory',
    '  help         Show this message',
    '',
    `Analysis engine: ${CORE_PACKAGE_NAME}`,
    `Severities: ${SEVERITIES.join(', ')}`,
  ].join('\n');
}

/** Runs the CLI and returns the process exit code (0 = success, 1 = usage error). */
export function runCli(argv: readonly string[], write: OutputWriter = defaultWriter): number {
  const [command = 'help', ...rest] = argv;

  if (rest.length > 0) {
    write(`Unexpected argument: ${rest.join(' ')}`);
    write(usage());
    return 1;
  }

  switch (command) {
    case 'help':
    case '--help':
    case '-h':
      write(usage());
      return 0;
    case 'analyze':
      write('analyze is not implemented yet. Coming in a later prompt.');
      return 0;
    default:
      write(`Unknown command: ${command}`);
      write(usage());
      return 1;
  }
}
