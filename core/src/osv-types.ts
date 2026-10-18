/** Structural types for the subset of the OSV API that depscan reads. */

export interface OsvPackageRef {
  readonly name?: string;
  readonly ecosystem?: string;
}

export interface OsvEvent {
  readonly introduced?: string;
  readonly fixed?: string;
  readonly last_affected?: string;
  readonly limit?: string;
}

export interface OsvRange {
  readonly type?: string;
  readonly events?: readonly OsvEvent[];
}

export interface OsvAffected {
  readonly package?: OsvPackageRef;
  readonly ranges?: readonly OsvRange[];
  readonly versions?: readonly string[];
  readonly database_specific?: Readonly<Record<string, unknown>>;
}

export interface OsvSeverityEntry {
  readonly type?: string;
  readonly score?: string;
}

export interface OsvReference {
  readonly type?: string;
  readonly url?: string;
}

export interface OsvVulnerability {
  readonly id?: string;
  readonly aliases?: readonly string[];
  readonly summary?: string;
  readonly details?: string;
  readonly severity?: readonly OsvSeverityEntry[];
  readonly affected?: readonly OsvAffected[];
  readonly references?: readonly OsvReference[];
  readonly database_specific?: Readonly<Record<string, unknown>>;
  readonly published?: string;
  readonly modified?: string;
}

export interface OsvQuery {
  /** OSV ecosystem name, e.g. `npm` or `PyPI`. */
  readonly ecosystem: string;
  readonly name: string;
  readonly version: string;
}
