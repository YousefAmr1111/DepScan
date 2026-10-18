const TYPE_CHECKS = {
    object: (value) => typeof value === 'object' && value !== null && !Array.isArray(value),
    array: (value) => Array.isArray(value),
    string: (value) => typeof value === 'string',
    boolean: (value) => typeof value === 'boolean',
    number: (value) => typeof value === 'number' && Number.isFinite(value),
    integer: (value) => typeof value === 'number' && Number.isInteger(value),
    null: (value) => value === null,
};
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function matchesType(value, type) {
    return typeof type === 'string'
        ? TYPE_CHECKS[type](value)
        : type.some((candidate) => TYPE_CHECKS[candidate](value));
}
function describeType(type) {
    return typeof type === 'string' ? type : type.join('|');
}
function describeValue(value) {
    if (value === null)
        return 'null';
    if (Array.isArray(value))
        return 'array';
    return typeof value;
}
/** Structural equality for JSON values. Used by `const`, `enum` and `uniqueItems`. */
export function isDeepEqual(left, right) {
    if (left === right)
        return true;
    if (Array.isArray(left) && Array.isArray(right)) {
        return (left.length === right.length && left.every((item, index) => isDeepEqual(item, right[index])));
    }
    if (isRecord(left) && isRecord(right)) {
        const leftKeys = Object.keys(left);
        const rightKeys = Object.keys(right);
        return (leftKeys.length === rightKeys.length &&
            leftKeys.every((key) => Object.hasOwn(right, key) && isDeepEqual(left[key], right[key])));
    }
    return false;
}
function resolveRef(ref, defs, path, issues) {
    const prefix = '#/$defs/';
    if (!ref.startsWith(prefix)) {
        issues.push({
            path,
            message: `unsupported $ref "${ref}": only "${prefix}<name>" is supported`,
        });
        return undefined;
    }
    const target = defs[ref.slice(prefix.length)];
    if (target === undefined) {
        issues.push({ path, message: `unresolved $ref "${ref}"` });
    }
    return target;
}
function countMatches(value, schemas, defs) {
    return schemas.filter((sub) => collectIssues(value, sub, defs, '').length === 0).length;
}
function collectIssues(value, schema, defs, path) {
    const issues = [];
    walk(value, schema, defs, path, issues);
    return issues;
}
function checkString(value, schema, path, issues) {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
        issues.push({ path, message: `must be at least ${schema.minLength} characters` });
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
        issues.push({ path, message: `must be at most ${schema.maxLength} characters` });
    }
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(value)) {
        issues.push({ path, message: `must match /${schema.pattern}/` });
    }
}
function checkNumber(value, schema, path, issues) {
    if (schema.minimum !== undefined && value < schema.minimum) {
        issues.push({ path, message: `must be >= ${schema.minimum}` });
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
        issues.push({ path, message: `must be <= ${schema.maximum}` });
    }
}
function checkArray(value, schema, defs, path, issues) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
        issues.push({ path, message: `must contain at least ${schema.minItems} items` });
    }
    if (schema.uniqueItems === true) {
        for (let index = 0; index < value.length; index += 1) {
            for (let other = index + 1; other < value.length; other += 1) {
                if (isDeepEqual(value[index], value[other])) {
                    issues.push({ path, message: `items ${index} and ${other} must be unique` });
                }
            }
        }
    }
    if (schema.items !== undefined) {
        value.forEach((item, index) => {
            walk(item, schema.items, defs, `${path}/${index}`, issues);
        });
    }
}
function checkObject(value, schema, defs, path, issues) {
    for (const key of schema.required ?? []) {
        if (!Object.hasOwn(value, key)) {
            issues.push({ path, message: `is missing required property "${key}"` });
        }
    }
    for (const [key, entry] of Object.entries(value)) {
        const known = schema.properties?.[key];
        if (known !== undefined) {
            walk(entry, known, defs, `${path}/${key}`, issues);
            continue;
        }
        if (schema.additionalProperties === false) {
            issues.push({ path, message: `has unknown property "${key}"` });
        }
        else if (typeof schema.additionalProperties === 'object') {
            walk(entry, schema.additionalProperties, defs, `${path}/${key}`, issues);
        }
    }
}
function walk(value, schema, defs, path, issues) {
    if (schema.$ref !== undefined) {
        const resolved = resolveRef(schema.$ref, defs, path, issues);
        if (resolved !== undefined) {
            walk(value, resolved, defs, path, issues);
        }
        return;
    }
    for (const sub of schema.allOf ?? []) {
        walk(value, sub, defs, path, issues);
    }
    if (schema.anyOf !== undefined && countMatches(value, schema.anyOf, defs) === 0) {
        issues.push({ path, message: 'does not match any of the allowed schemas' });
        for (const sub of schema.anyOf) {
            walk(value, sub, defs, path, issues);
        }
    }
    if (schema.oneOf !== undefined) {
        const matches = countMatches(value, schema.oneOf, defs);
        if (matches === 0) {
            issues.push({ path, message: 'does not match any of the allowed schemas' });
            for (const sub of schema.oneOf) {
                walk(value, sub, defs, path, issues);
            }
        }
        else if (matches > 1) {
            issues.push({ path, message: `matches ${matches} schemas but must match exactly one` });
        }
    }
    if (schema.const !== undefined && !isDeepEqual(value, schema.const)) {
        issues.push({ path, message: `must be ${JSON.stringify(schema.const)}` });
    }
    if (schema.enum !== undefined && !schema.enum.some((allowed) => isDeepEqual(value, allowed))) {
        const options = schema.enum.map((allowed) => JSON.stringify(allowed)).join(', ');
        issues.push({ path, message: `must be one of ${options}` });
    }
    if (schema.type !== undefined && !matchesType(value, schema.type)) {
        issues.push({
            path,
            message: `must be ${describeType(schema.type)}, received ${describeValue(value)}`,
        });
        return;
    }
    if (typeof value === 'string') {
        checkString(value, schema, path, issues);
    }
    else if (typeof value === 'number') {
        checkNumber(value, schema, path, issues);
    }
    if (Array.isArray(value)) {
        checkArray(value, schema, defs, path, issues);
    }
    else if (isRecord(value)) {
        checkObject(value, schema, defs, path, issues);
    }
}
/** Validates `value` against `schema`, returning every issue found (empty when valid). */
export function validateJsonSchema(value, schema) {
    return collectIssues(value, schema, schema.$defs ?? {}, '');
}
//# sourceMappingURL=json-schema.js.map