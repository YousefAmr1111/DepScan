/**
 * CVSS base score calculation, enough for severity mapping.
 *
 * v3.0 and v3.1 are implemented exactly, following the specification's constants and
 * `Roundup`. CVSS v4.0 returns `null`: its base score is defined by a macrovector lookup
 * table that cannot be derived from the vector string, and inventing a number would be
 * worse than reporting that the score is unavailable. See docs/p05-decisions.md.
 */
const ATTACK_VECTOR = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const ATTACK_COMPLEXITY = { L: 0.77, H: 0.44 };
const PRIVILEGES_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const PRIVILEGES_CHANGED = { N: 0.85, L: 0.68, H: 0.5 };
const USER_INTERACTION = { N: 0.85, R: 0.62 };
const IMPACT = { H: 0.56, L: 0.22, N: 0 };
/** Parses a CVSS vector string. Returns null when the string is not a CVSS vector. */
export function parseCvssVector(vector) {
    const parts = vector.split('/');
    const prefix = parts[0];
    if (prefix === undefined) {
        return null;
    }
    const version = prefix.startsWith('CVSS:4.0')
        ? '4.0'
        : prefix.startsWith('CVSS:3.1')
            ? '3.1'
            : prefix.startsWith('CVSS:3.0')
                ? '3.0'
                : null;
    if (version === null) {
        return null;
    }
    const metrics = {};
    for (const part of parts.slice(1)) {
        const [key, value] = part.split(':');
        if (key !== undefined && value !== undefined) {
            metrics[key] = value;
        }
    }
    return { version, metrics };
}
/** CVSS 3.1 Roundup: round to one decimal, always upwards. */
function roundUp(value) {
    const scaled = Math.round(value * 100_000);
    if (scaled % 10_000 === 0) {
        return scaled / 100_000;
    }
    return (Math.floor(scaled / 10_000) + 1) / 10;
}
/** The CVSS v3.0/v3.1 base score, or null when a required metric is missing. */
export function cvss3BaseScore(vector) {
    if (vector.version !== '3.0' && vector.version !== '3.1') {
        return null;
    }
    const { metrics } = vector;
    const attackVector = ATTACK_VECTOR[metrics['AV'] ?? ''];
    const attackComplexity = ATTACK_COMPLEXITY[metrics['AC'] ?? ''];
    const privileges = metrics['PR'] === undefined ? undefined : PRIVILEGES_UNCHANGED[metrics['PR']];
    const privilegesChanged = metrics['PR'] === undefined ? undefined : PRIVILEGES_CHANGED[metrics['PR']];
    const userInteraction = USER_INTERACTION[metrics['UI'] ?? ''];
    const scopeChanged = metrics['S'] === 'C';
    const confidentiality = IMPACT[metrics['C'] ?? ''];
    const integrity = IMPACT[metrics['I'] ?? ''];
    const availability = IMPACT[metrics['A'] ?? ''];
    if (attackVector === undefined ||
        attackComplexity === undefined ||
        userInteraction === undefined ||
        confidentiality === undefined ||
        integrity === undefined ||
        availability === undefined ||
        (privileges === undefined && privilegesChanged === undefined)) {
        return null;
    }
    const effectivePrivileges = scopeChanged ? privilegesChanged : privileges;
    if (effectivePrivileges === undefined) {
        return null;
    }
    const impactSubScore = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability);
    const impact = scopeChanged === true
        ? 7.52 * (impactSubScore - 0.029) - 3.25 * (impactSubScore - 0.02) ** 15
        : 6.42 * impactSubScore;
    if (impact <= 0) {
        return 0;
    }
    const exploitability = 8.22 * attackVector * attackComplexity * effectivePrivileges * userInteraction;
    const score = scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability;
    return Math.min(roundUp(Math.min(score, 10)), 10);
}
/**
 * Base score for any CVSS vector, or null when it cannot be derived. Callers must treat
 * null as "unknown", never as zero.
 */
export function cvssBaseScore(vector) {
    const parsed = parseCvssVector(vector);
    return parsed === null ? null : cvss3BaseScore(parsed);
}
//# sourceMappingURL=cvss.js.map