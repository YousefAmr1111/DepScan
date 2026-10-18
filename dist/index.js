export { CORE_PACKAGE_NAME, ECOSYSTEMS, REPORT_SCHEMA_VERSION, SEVERITIES, TOOL_NAME, UNRESOLVED_REASONS, } from './types.js';
export { compareSeverity, isSeverity, sortVulnerabilitiesBySeverity } from './severity.js';
export { computeStats, countBySeverity, emptySeverityCounts } from './stats.js';
export { isDeepEqual, validateJsonSchema } from './json-schema.js';
export { REPORT_SCHEMA } from './report-schema.js';
export { isReport, validateReport } from './validate-report.js';
export { PARSE_ERROR_CODES, ProjectParseError, isProjectParseError } from './errors.js';
export { comparePackageEntries, compareVersions, packageId, sortPackageEntries, splitPackageId, } from './package-key.js';
export { SUPPORTED_LOCKFILE_VERSIONS, parseNpm } from './npm-parse.js';
export { normalizePythonName, parsePython } from './python-parse.js';
export { buildTree } from './build-tree.js';
export { cvss3BaseScore, cvssBaseScore, parseCvssVector } from './cvss.js';
export { cvssFromVectors, decideSeverity, severityFromCvssScore, severityFromGithubRating, } from './severity-map.js';
export { DEFAULT_BASE_DELAY_MS, DEFAULT_RETRIES, DEFAULT_TIMEOUT_MS, OSV_BATCH_ENDPOINT, OSV_ERROR_CODES, OSV_MAX_BATCH_SIZE, OsvError, createOsvHttp, isOsvError, } from './osv-http.js';
export { DEFAULT_CACHE_TTL_MS, OSV_CACHE_MISS_CODES, OsvCacheMissError, cacheKeyFor, createFileCache, createMemoryCache, defaultCacheDir, isOsvCacheMissError, } from './osv-cache.js';
export { OSV_SOURCE, matchVulnerabilities, osvEcosystemName, osvLookupName, recordCveIds, recordGhsaIds, } from './match.js';
//# sourceMappingURL=index.js.map