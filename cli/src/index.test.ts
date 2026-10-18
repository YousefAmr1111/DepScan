import { describe, expect, it } from 'vitest';

import { runCli, usage } from './index.js';

function collect(): { lines: string[]; write: (line: string) => void } {
  const lines: string[] = [];
  return { lines, write: (line) => lines.push(line) };
}

describe('runCli', () => {
  it('prints usage and exits successfully for help', () => {
    const { lines, write } = collect();

    expect(runCli(['help'], write)).toBe(0);
    expect(lines).toEqual([usage()]);
  });

  it('defaults to help when no arguments are given', () => {
    const { lines, write } = collect();

    expect(runCli([], write)).toBe(0);
    expect(lines[0]).toContain('Usage: depscan');
  });

  it('supports the --help flag', () => {
    const { lines, write } = collect();

    expect(runCli(['--help'], write)).toBe(0);
    expect(lines[0]).toContain('Usage: depscan');
  });

  it('fails on unknown commands', () => {
    const { lines, write } = collect();

    expect(runCli(['audit'], write)).toBe(1);
    expect(lines[0]).toBe('Unknown command: audit');
  });

  it('rejects trailing arguments', () => {
    const { lines, write } = collect();

    expect(runCli(['analyze', 'extra'], write)).toBe(1);
    expect(lines[0]).toBe('Unexpected argument: extra');
  });

  it('lists analyze as the command that runs the engine', () => {
    expect(usage()).toContain('analyze <dir>');
  });

  it('no longer accepts the old scan command name', () => {
    const { lines, write } = collect();

    expect(runCli(['scan'], write)).toBe(1);
    expect(lines[0]).toBe('Unknown command: scan');
  });

  it('surfaces the engine package name it delegates to', () => {
    expect(usage()).toContain('Analysis engine: @depscan/core');
  });
});
