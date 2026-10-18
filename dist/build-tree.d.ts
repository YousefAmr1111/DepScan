import type { PackageEntry } from './types.js';
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
/**
 * Turns the flat, `name@version`-keyed package list into a structure the dashboard can
 * render. A package with several parents appears under each of them; an id already on the
 * current path is not expanded again, so a dependency cycle cannot loop forever.
 */
export declare function buildTree(packages: readonly PackageEntry[]): PackageTree;
//# sourceMappingURL=build-tree.d.ts.map