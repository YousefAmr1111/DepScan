import { comparePackageEntries, packageId } from './package-key.js';
import type { PackageEntry } from './types.js';

/** Safety valve so a pathological graph cannot expand without bound. */
const MAX_EXPANDED_NODES = 10_000;

export interface PackageTreeNode {
  /** `name@version`, the same key used in `PackageEntry.parents`. */
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly isDirect: boolean;
  readonly depth: number;
  readonly parentIds: readonly string[];
  readonly childIds: readonly string[];
  /**
   * Only populated on the nodes returned in `PackageTree.roots`. Nodes in
   * `PackageTree.nodes` carry relationships and an empty `children`, so a renderer can
   * walk the graph itself without paying for a second expanded copy.
   */
  readonly children: readonly PackageTreeNode[];
}

export interface PackageTree {
  /** Ids of the packages the project depends on directly, plus anything unlinked. */
  readonly rootIds: readonly string[];
  /** The same roots as `rootIds`, expanded for rendering. */
  readonly roots: readonly PackageTreeNode[];
  /** One node per `name@version`, for graph rendering. */
  readonly nodes: ReadonlyMap<string, PackageTreeNode>;
}

function compareIds(
  byId: ReadonlyMap<string, PackageEntry>,
): (left: string, right: string) => number {
  return (left, right) => {
    const leftEntry = byId.get(left);
    const rightEntry = byId.get(right);
    if (leftEntry === undefined || rightEntry === undefined) {
      return left.localeCompare(right);
    }
    return comparePackageEntries(leftEntry, rightEntry);
  };
}

/**
 * Turns the flat, `name@version`-keyed package list into a structure the dashboard can
 * render. A package with several parents appears under each of them; an id already on the
 * current path is not expanded again, so a dependency cycle cannot loop forever.
 */
export function buildTree(packages: readonly PackageEntry[]): PackageTree {
  const byId = new Map<string, PackageEntry>();
  for (const entry of packages) {
    byId.set(packageId(entry.name, entry.version), entry);
  }
  const byIdOrder = compareIds(byId);

  const parentIds = new Map<string, string[]>();
  const childIds = new Map<string, string[]>();
  for (const [id, entry] of byId) {
    parentIds.set(id, [...new Set(entry.parents)].sort(byIdOrder));
  }
  for (const [id, parents] of parentIds) {
    for (const parentId of parents) {
      const children = childIds.get(parentId) ?? [];
      if (!children.includes(id)) {
        children.push(id);
      }
      childIds.set(parentId, children);
    }
  }
  for (const [parentId, children] of childIds) {
    childIds.set(parentId, children.sort(byIdOrder));
  }

  const nodes = new Map<string, PackageTreeNode>();
  for (const [id, entry] of byId) {
    nodes.set(id, {
      id,
      name: entry.name,
      version: entry.version,
      isDirect: entry.isDirect,
      depth: entry.depth,
      parentIds: parentIds.get(id) ?? [],
      childIds: childIds.get(id) ?? [],
      children: [],
    });
  }

  const rootIds = [...byId.entries()]
    .filter(
      ([, entry]) =>
        entry.isDirect || entry.parents.length === 0 || entry.parents.every((id) => !byId.has(id)),
    )
    .map(([id]) => id)
    .sort(byIdOrder);

  let expanded = 0;
  const expand = (id: string, onPath: ReadonlySet<string>): PackageTreeNode => {
    const node = nodes.get(id);
    if (node === undefined) {
      return {
        id,
        name: id,
        version: '',
        isDirect: false,
        depth: 0,
        parentIds: [],
        childIds: [],
        children: [],
      };
    }
    if (onPath.has(id) || expanded >= MAX_EXPANDED_NODES) {
      return node;
    }
    expanded += 1;
    const path = new Set(onPath).add(id);
    const children = node.childIds
      .filter((childId) => !path.has(childId))
      .map((childId) => expand(childId, path));

    return { ...node, children };
  };

  const roots = rootIds.map((id) => expand(id, new Set()));

  return { rootIds, roots, nodes };
}
