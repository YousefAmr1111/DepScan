import { describe, expect, it } from 'vitest';

import { buildTree, type PackageEntry } from './index.js';

function entry(
  name: string,
  version: string,
  isDirect: boolean,
  depth: number,
  parents: readonly string[] = [],
): PackageEntry {
  return { name, version, isDirect, depth, parents, isDev: null };
}

const CHAIN = [
  entry('app', '1.0.0', true, 0),
  entry('lib', '2.0.0', false, 1, ['app@1.0.0']),
  entry('util', '3.0.0', false, 2, ['lib@2.0.0']),
];

describe('buildTree', () => {
  it('treats the direct dependencies as the roots', () => {
    expect(buildTree(CHAIN).rootIds).toEqual(['app@1.0.0']);
  });

  it('expands the roots so a dashboard can render without walking the graph', () => {
    const [root] = buildTree(CHAIN).roots;

    expect(root?.id).toBe('app@1.0.0');
    expect(root?.children[0]?.id).toBe('lib@2.0.0');
    expect(root?.children[0]?.children[0]?.id).toBe('util@3.0.0');
  });

  it('carries the report fields through to each node', () => {
    const [util] = buildTree(CHAIN).roots.flatMap((root) =>
      root.children.flatMap((c) => c.children),
    );

    expect(util).toMatchObject({
      id: 'util@3.0.0',
      name: 'util',
      version: '3.0.0',
      isDirect: false,
      depth: 2,
      parentIds: ['lib@2.0.0'],
      childIds: [],
    });
  });

  it('lists the same package under every parent that requires it', () => {
    const shared = entry('shared', '1.0.0', false, 1, ['a@1.0.0', 'b@1.0.0']);
    const tree = buildTree([entry('a', '1.0.0', true, 0), entry('b', '1.0.0', true, 0), shared]);

    const parents = tree.roots.flatMap((root) => root.children.map((child) => child.id));

    expect(parents).toEqual(['shared@1.0.0', 'shared@1.0.0']);
    expect(tree.nodes.get('shared@1.0.0')?.parentIds).toEqual(['a@1.0.0', 'b@1.0.0']);
  });

  it('indexes every package by name@version for graph rendering', () => {
    const tree = buildTree(CHAIN);

    expect([...tree.nodes.keys()]).toEqual(['app@1.0.0', 'lib@2.0.0', 'util@3.0.0']);
    expect(tree.nodes.get('lib@2.0.0')?.childIds).toEqual(['util@3.0.0']);
  });

  it('leaves children empty on index nodes to avoid a second expanded copy', () => {
    expect(buildTree(CHAIN).nodes.get('app@1.0.0')?.children).toEqual([]);
  });

  it('does not loop forever on a dependency cycle', () => {
    const cyclic = [
      entry('a', '1.0.0', true, 0),
      entry('b', '1.0.0', false, 1, ['a@1.0.0']),
      entry('c', '1.0.0', false, 2, ['b@1.0.0']),
    ];
    const withBackEdge = cyclic.map((node) =>
      node.name === 'a' ? entry('a', '1.0.0', true, 0, ['c@1.0.0']) : node,
    );

    const [root] = buildTree(withBackEdge).roots;
    const grandchild = root?.children[0]?.children[0];

    expect(grandchild?.id).toBe('c@1.0.0');
    expect(grandchild?.children).toEqual([]);
  });

  it('treats a package with no parents as a root', () => {
    expect(buildTree([entry('lonely', '1.0.0', false, 0)]).rootIds).toEqual(['lonely@1.0.0']);
  });

  it('compares version segments numerically, so 1.9.0 sorts before 1.10.0', () => {
    const packages = [
      entry('b', '1.0.0', true, 0),
      entry('a', '1.0.0', true, 0),
      entry('a', '1.10.0', false, 1, ['b@1.0.0']),
      entry('a', '1.9.0', false, 1, ['b@1.0.0']),
    ];

    const tree = buildTree(packages);

    expect(tree.rootIds).toEqual(['a@1.0.0', 'b@1.0.0']);
    expect(tree.nodes.get('b@1.0.0')?.childIds).toEqual(['a@1.9.0', 'a@1.10.0']);
  });

  it('keeps a package whose parent is missing from the list', () => {
    const tree = buildTree([entry('child', '1.0.0', false, 1, ['ghost@1.0.0'])]);

    expect(tree.nodes.get('child@1.0.0')?.parentIds).toEqual(['ghost@1.0.0']);
    expect(tree.roots[0]?.id).toBe('child@1.0.0');
  });

  it('returns an empty tree for no packages', () => {
    const tree = buildTree([]);

    expect(tree.rootIds).toEqual([]);
    expect(tree.roots).toEqual([]);
    expect(tree.nodes.size).toBe(0);
  });
});
