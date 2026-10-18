export type JsonSchemaType =
  'object' | 'array' | 'string' | 'number' | 'integer' | 'boolean' | 'null';

/**
 * The subset of JSON Schema (draft 2020-12) used by depscan. Unsupported keywords are
 * deliberately absent so that a schema can never appear to validate more than this
 * validator actually enforces.
 */
export interface JsonSchema {
  readonly $schema?: string;
  readonly $id?: string;
  readonly $ref?: string;
  readonly title?: string;
  readonly description?: string;
  readonly $defs?: Readonly<Record<string, JsonSchema>>;
  readonly type?: JsonSchemaType | readonly JsonSchemaType[];
  readonly enum?: readonly unknown[];
  readonly const?: unknown;
  readonly properties?: Readonly<Record<string, JsonSchema>>;
  readonly required?: readonly string[];
  readonly additionalProperties?: boolean | JsonSchema;
  readonly items?: JsonSchema;
  readonly minItems?: number;
  readonly uniqueItems?: boolean;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly pattern?: string;
  readonly minimum?: number;
  readonly maximum?: number;
  readonly allOf?: readonly JsonSchema[];
  readonly anyOf?: readonly JsonSchema[];
  readonly oneOf?: readonly JsonSchema[];
}

export interface ValidationIssue {
  /** JSON Pointer to the offending value, e.g. `/vulnerabilities/0/severity`. */
  readonly path: string;
  readonly message: string;
}

const TYPE_CHECKS: Readonly<Record<JsonSchemaType, (value: unknown) => boolean>> = {
  object: (value) => typeof value === 'object' && value !== null && !Array.isArray(value),
  array: (value) => Array.isArray(value),
  string: (value) => typeof value === 'string',
  boolean: (value) => typeof value === 'boolean',
  number: (value) => typeof value === 'number' && Number.isFinite(value),
  integer: (value) => typeof value === 'number' && Number.isInteger(value),
  null: (value) => value === null,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function matchesType(value: unknown, type: JsonSchemaType | readonly JsonSchemaType[]): boolean {
  return typeof type === 'string'
    ? TYPE_CHECKS[type](value)
    : type.some((candidate) => TYPE_CHECKS[candidate](value));
}

function describeType(type: JsonSchemaType | readonly JsonSchemaType[]): string {
  return typeof type === 'string' ? type : type.join('|');
}

function describeValue(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

/** Structural equality for JSON values. Used by `const`, `enum` and `uniqueItems`. */
export function isDeepEqual(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (Array.isArray(left) && Array.isArray(right)) {
    return (
      left.length === right.length && left.every((item, index) => isDeepEqual(item, right[index]))
    );
  }
  if (isRecord(left) && isRecord(right)) {
    const leftKeys = Object.keys(left);
    const rightKeys = Object.keys(right);
    return (
      leftKeys.length === rightKeys.length &&
      leftKeys.every((key) => Object.hasOwn(right, key) && isDeepEqual(left[key], right[key]))
    );
  }
  return false;
}

function resolveRef(
  ref: string,
  defs: Readonly<Record<string, JsonSchema>>,
  path: string,
  issues: ValidationIssue[],
): JsonSchema | undefined {
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

function countMatches(
  value: unknown,
  schemas: readonly JsonSchema[],
  defs: Readonly<Record<string, JsonSchema>>,
): number {
  return schemas.filter((sub) => collectIssues(value, sub, defs, '').length === 0).length;
}

function collectIssues(
  value: unknown,
  schema: JsonSchema,
  defs: Readonly<Record<string, JsonSchema>>,
  path: string,
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  walk(value, schema, defs, path, issues);
  return issues;
}

function checkString(
  value: string,
  schema: JsonSchema,
  path: string,
  issues: ValidationIssue[],
): void {
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

function checkNumber(
  value: number,
  schema: JsonSchema,
  path: string,
  issues: ValidationIssue[],
): void {
  if (schema.minimum !== undefined && value < schema.minimum) {
    issues.push({ path, message: `must be >= ${schema.minimum}` });
  }
  if (schema.maximum !== undefined && value > schema.maximum) {
    issues.push({ path, message: `must be <= ${schema.maximum}` });
  }
}

function checkArray(
  value: readonly unknown[],
  schema: JsonSchema,
  defs: Readonly<Record<string, JsonSchema>>,
  path: string,
  issues: ValidationIssue[],
): void {
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
      walk(item, schema.items as JsonSchema, defs, `${path}/${index}`, issues);
    });
  }
}

function checkObject(
  value: Record<string, unknown>,
  schema: JsonSchema,
  defs: Readonly<Record<string, JsonSchema>>,
  path: string,
  issues: ValidationIssue[],
): void {
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
    } else if (typeof schema.additionalProperties === 'object') {
      walk(entry, schema.additionalProperties, defs, `${path}/${key}`, issues);
    }
  }
}

function walk(
  value: unknown,
  schema: JsonSchema,
  defs: Readonly<Record<string, JsonSchema>>,
  path: string,
  issues: ValidationIssue[],
): void {
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
    } else if (matches > 1) {
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
  } else if (typeof value === 'number') {
    checkNumber(value, schema, path, issues);
  }

  if (Array.isArray(value)) {
    checkArray(value, schema, defs, path, issues);
  } else if (isRecord(value)) {
    checkObject(value, schema, defs, path, issues);
  }
}

/** Validates `value` against `schema`, returning every issue found (empty when valid). */
export function validateJsonSchema(value: unknown, schema: JsonSchema): ValidationIssue[] {
  return collectIssues(value, schema, schema.$defs ?? {}, '');
}
