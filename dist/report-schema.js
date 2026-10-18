import { REPORT_SCHEMA_VERSION, UNRESOLVED_REASONS } from './types.js';
const def = (name) => ({ $ref: `#/$defs/${name}` });
/** Lowercase, dot/dash separated, with no spaces: `osv.dev`, `npm-audit`, `github`. */
const SOURCE_PATTERN = '^[a-z0-9]+([.-][a-z0-9]+)*$';
/** Package and project names are opaque: whitespace-free and length-bounded only. */
const NAME_PATTERN = '^\\S+$';
/** `name@version` of an installed package, e.g. `express@4.18.2`. */
const PARENT_REF_PATTERN = '^[^@\\s]+@[^@\\s]+$';
const ADVISORY_URL_PATTERN = '^https://\\S+$';
const REASON_CODE_PATTERN = '^[a-z0-9]+([._-][a-z0-9]+)*$';
const TIMESTAMP_PATTERN = '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,3})?Z$';
const CVE_OR_GHSA_PATTERN = '^(CVE-[0-9]{4}-[0-9]{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$';
/** JSON Schema for report.json, draft 2020-12. Mirrors the types in `./types.ts`. */
export const REPORT_SCHEMA = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://depscan.local/schema/report.schema.json',
    title: 'depscan report',
    description: 'Dependency scan report. The engine (packages/core) decides every finding; the ' +
        'LLM layer may only fill the suggestions section.',
    type: 'object',
    additionalProperties: false,
    required: [
        'schemaVersion',
        'meta',
        'packages',
        'vulnerabilities',
        'risk',
        'suggestions',
        'stats',
    ],
    properties: {
        schemaVersion: { const: REPORT_SCHEMA_VERSION },
        meta: def('meta'),
        packages: { type: 'array', items: def('packageEntry') },
        vulnerabilities: { type: 'array', items: def('vulnerability') },
        risk: { type: 'array', items: def('riskAssessment') },
        suggestions: { type: 'array', items: def('suggestion') },
        stats: def('stats'),
    },
    $defs: {
        name: { type: 'string', minLength: 1, maxLength: 214, pattern: NAME_PATTERN },
        version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            description: 'Opaque version string. Not pattern-checked: npm and PyPI version syntax differ.',
        },
        timestamp: {
            type: 'string',
            pattern: TIMESTAMP_PATTERN,
            description: 'ISO-8601 timestamp in UTC, e.g. 2026-02-14T09:30:00Z.',
        },
        severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
        meta: {
            type: 'object',
            additionalProperties: false,
            required: [
                'tool',
                'generatedAt',
                'projectName',
                'ecosystem',
                'manifestPath',
                'unresolved',
                'warnings',
            ],
            properties: {
                tool: {
                    type: 'object',
                    additionalProperties: false,
                    required: ['name', 'version'],
                    properties: {
                        name: { const: 'depscan' },
                        version: { type: 'string', minLength: 1, maxLength: 32 },
                    },
                },
                generatedAt: def('timestamp'),
                projectName: { type: 'string', minLength: 1, maxLength: 214, pattern: NAME_PATTERN },
                ecosystem: { type: 'string', enum: ['npm', 'pypi'] },
                manifestPath: {
                    type: 'string',
                    minLength: 1,
                    maxLength: 1024,
                    pattern: '^[^\\\\]+$',
                    description: 'Path to the scanned manifest, relative and using forward slashes.',
                },
                unresolved: {
                    type: 'array',
                    items: def('unresolvedRequirement'),
                    description: 'Requirements that could not be resolved, so could not be checked.',
                },
                warnings: {
                    type: 'array',
                    items: { type: 'string', minLength: 1, maxLength: 512 },
                    description: 'Recoverable problems reported by the parsers.',
                },
            },
        },
        unresolvedRequirement: {
            type: 'object',
            additionalProperties: false,
            required: ['raw', 'name', 'specifier', 'line', 'reason'],
            properties: {
                raw: { type: 'string', minLength: 1, maxLength: 512 },
                name: {
                    type: 'string',
                    maxLength: 214,
                    description: 'Empty when the line declares no package.',
                },
                specifier: { type: 'string', maxLength: 512 },
                line: { type: 'integer', minimum: 1 },
                reason: { type: 'string', enum: [...UNRESOLVED_REASONS] },
            },
        },
        packageEntry: {
            type: 'object',
            additionalProperties: false,
            required: ['name', 'version', 'isDirect', 'depth', 'parents', 'isDev'],
            properties: {
                name: def('name'),
                version: def('version'),
                isDirect: { type: 'boolean' },
                depth: { type: 'integer', minimum: 0, description: '0 for direct dependencies.' },
                parents: {
                    type: 'array',
                    uniqueItems: true,
                    items: { type: 'string', pattern: PARENT_REF_PATTERN },
                },
                isDev: {
                    type: ['boolean', 'null'],
                    description: 'null when the ecosystem has no dev/prod distinction, such as PyPI.',
                },
            },
        },
        vulnerability: {
            type: 'object',
            additionalProperties: false,
            required: [
                'id',
                'aliases',
                'package',
                'installedVersion',
                'severity',
                'cvss',
                'summary',
                'affectedRange',
                'fixedVersion',
                'advisoryUrl',
                'source',
            ],
            properties: {
                id: { type: 'string', pattern: CVE_OR_GHSA_PATTERN },
                aliases: {
                    type: 'array',
                    uniqueItems: true,
                    items: { type: 'string', minLength: 1, maxLength: 64 },
                },
                package: def('name'),
                installedVersion: def('version'),
                severity: def('severity'),
                cvss: {
                    anyOf: [{ type: 'null' }, def('cvss')],
                },
                summary: { type: 'string', minLength: 1, maxLength: 1024 },
                affectedRange: { type: 'string', minLength: 1, maxLength: 256 },
                fixedVersion: { anyOf: [{ type: 'null' }, def('version')] },
                advisoryUrl: {
                    anyOf: [{ type: 'null' }, { type: 'string', pattern: ADVISORY_URL_PATTERN }],
                },
                source: { type: 'string', minLength: 1, maxLength: 32, pattern: SOURCE_PATTERN },
            },
        },
        cvss: {
            type: 'object',
            additionalProperties: false,
            required: ['score', 'vector'],
            properties: {
                score: { type: 'number', minimum: 0, maximum: 10 },
                vector: { type: 'string', minLength: 1, maxLength: 128 },
            },
        },
        riskAssessment: {
            type: 'object',
            additionalProperties: false,
            required: ['vulnerabilityId', 'priorityScore', 'flags', 'reasons'],
            properties: {
                vulnerabilityId: { type: 'string', pattern: CVE_OR_GHSA_PATTERN },
                priorityScore: { type: 'integer', minimum: 0, maximum: 100 },
                flags: def('riskFlags'),
                reasons: {
                    type: 'array',
                    minItems: 1,
                    uniqueItems: true,
                    items: { type: 'string', pattern: REASON_CODE_PATTERN },
                },
            },
        },
        riskFlags: {
            type: 'object',
            additionalProperties: false,
            required: ['isReachable', 'isDirect', 'hasFix'],
            properties: {
                isReachable: { type: 'boolean' },
                isDirect: { type: 'boolean' },
                hasFix: { type: 'boolean' },
            },
        },
        suggestion: {
            type: 'object',
            additionalProperties: false,
            required: ['vulnerabilityId', 'saferVersion', 'alternativePackage', 'rationale', 'provider'],
            description: 'Written by the LLM layer only. Never by the engine.',
            properties: {
                vulnerabilityId: { type: 'string', pattern: CVE_OR_GHSA_PATTERN },
                saferVersion: { anyOf: [{ type: 'null' }, def('version')] },
                alternativePackage: { anyOf: [{ type: 'null' }, def('name')] },
                rationale: { type: 'string', minLength: 1, maxLength: 2048 },
                provider: { const: 'llm' },
            },
            anyOf: [
                { properties: { saferVersion: def('version') }, required: ['saferVersion'] },
                { properties: { alternativePackage: def('name') }, required: ['alternativePackage'] },
            ],
        },
        stats: {
            type: 'object',
            additionalProperties: false,
            required: [
                'totalPackages',
                'directPackages',
                'transitivePackages',
                'totalVulnerabilities',
                'bySeverity',
                'unresolvedCount',
            ],
            properties: {
                totalPackages: { type: 'integer', minimum: 0 },
                directPackages: { type: 'integer', minimum: 0 },
                transitivePackages: { type: 'integer', minimum: 0 },
                totalVulnerabilities: { type: 'integer', minimum: 0 },
                unresolvedCount: { type: 'integer', minimum: 0 },
                bySeverity: {
                    type: 'object',
                    additionalProperties: false,
                    required: ['critical', 'high', 'medium', 'low'],
                    properties: {
                        critical: { type: 'integer', minimum: 0 },
                        high: { type: 'integer', minimum: 0 },
                        medium: { type: 'integer', minimum: 0 },
                        low: { type: 'integer', minimum: 0 },
                    },
                },
            },
        },
    },
};
//# sourceMappingURL=report-schema.js.map