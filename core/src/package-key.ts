import type { PackageEntry } from './types.js';

/** Canonical key for a package instance: `name@version`, e.g. `ms@2.1.2`. */
export function packageId(name: string, version: string): string {
  return `${name}@${version}`;
}

/**
 * Splits `name@version`, tolerating a scoped name such as `@scope/pkg@1.2.3` by taking
 * the last `@`. Returns null when there is no version part.
 */
export function splitPackageId(
  id: string,
): { readonly name: string; readonly version: string } | null {
  const separator = id.lastIndexOf('@');
  if (separator <= 0) {
    return null;
  }
  return { name: id.slice(0, separator), version: id.slice(separator + 1) };
}

/**
 * Compares dotted version strings numerically where possible (`4.9.0` < `4.17.0`).
 * Deterministic, not a full semver implementation: pre-release ordering is not modelled.
 */
export function compareVersions(left: string, right: string): number {
  const leftParts = left.split(/[.+-]/u);
  const rightParts = right.split(/[.+-]/u);
  const length = Math.max(leftParts.length, rightParts.length);

  for (let index = 0; index < length; index += 1) {
    const a = leftParts[index] ?? '';
    const b = rightParts[index] ?? '';
    const aNumber = Number.parseInt(a, 10);
    const bNumber = Number.parseInt(b, 10);
    const aIsNumber = a !== '' && !Number.isNaN(aNumber);
    const bIsNumber = b !== '' && !Number.isNaN(bNumber);

    if (aIsNumber && bIsNumber) {
      if (aNumber !== bNumber) return aNumber - bNumber;
      continue;
    }
    if (a !== b) return a < b ? -1 : 1;
  }

  return 0;
}

/** Total order over package instances: by name, then by version. Required for §1.5. */
export function comparePackageEntries(left: PackageEntry, right: PackageEntry): number {
  if (left.name !== right.name) return left.name < right.name ? -1 : 1;
  return compareVersions(left.version, right.version);
}

export function sortPackageEntries(packages: readonly PackageEntry[]): PackageEntry[] {
  return [...packages].sort(comparePackageEntries);
}
