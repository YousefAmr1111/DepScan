import { describe, expect, it } from 'vitest';

import { isDeepEqual, validateJsonSchema, type JsonSchema } from './index.js';

const objectSchema: JsonSchema = {
  type: 'object',
  required: ['name'],
  additionalProperties: false,
  properties: { name: { type: 'string', minLength: 2 } },
};

describe('validateJsonSchema', () => {
  it('returns no issues for a value that satisfies the schema', () => {
    expect(validateJsonSchema({ name: 'depscan' }, objectSchema)).toEqual([]);
  });

  it('reports the path of a nested type mismatch', () => {
    const issues = validateJsonSchema({ name: 7 }, objectSchema);

    expect(issues).toHaveLength(1);
    expect(issues[0]?.path).toBe('/name');
    expect(issues[0]?.message).toContain('must be string');
  });

  it('reports missing required properties', () => {
    const issues = validateJsonSchema({}, objectSchema);

    expect(issues[0]?.path).toBe('');
    expect(issues[0]?.message).toContain('missing required property "name"');
  });

  it('rejects unknown properties when additionalProperties is false', () => {
    const issues = validateJsonSchema({ name: 'ok', extra: 1 }, objectSchema);

    expect(issues[0]?.message).toContain('unknown property "extra"');
  });

  it('validates additionalProperties against a nested schema when one is given', () => {
    const schema: JsonSchema = { type: 'object', additionalProperties: { type: 'number' } };

    expect(validateJsonSchema({ a: 1 }, schema)).toEqual([]);
    expect(validateJsonSchema({ a: 'x' }, schema)[0]?.path).toBe('/a');
  });

  it('enforces minLength on strings', () => {
    expect(validateJsonSchema({ name: 'a' }, objectSchema)[0]?.message).toContain(
      'at least 2 characters',
    );
  });

  it('validates array items and reports the failing index', () => {
    const schema: JsonSchema = { type: 'array', items: { type: 'string' } };

    expect(validateJsonSchema(['a', 2], schema)[0]?.path).toBe('/1');
  });

  it('enforces minItems', () => {
    const schema: JsonSchema = { type: 'array', minItems: 1 };

    expect(validateJsonSchema([], schema)[0]?.message).toContain('at least 1 items');
  });

  it('enforces uniqueItems', () => {
    const schema: JsonSchema = { type: 'array', uniqueItems: true };

    expect(validateJsonSchema([1, 2], schema)).toEqual([]);
    expect(validateJsonSchema([1, 1], schema)[0]?.message).toContain('must be unique');
  });

  it('enforces enum membership', () => {
    const schema: JsonSchema = { type: 'string', enum: ['npm', 'pypi'] };

    expect(validateJsonSchema('npm', schema)).toEqual([]);
    expect(validateJsonSchema('cargo', schema)[0]?.message).toContain(
      'must be one of "npm", "pypi"',
    );
  });

  it('enforces const', () => {
    const schema: JsonSchema = { const: 1 };

    expect(validateJsonSchema(1, schema)).toEqual([]);
    expect(validateJsonSchema(2, schema)[0]?.message).toContain('must be 1');
  });

  it('enforces numeric bounds', () => {
    const schema: JsonSchema = { type: 'integer', minimum: 0, maximum: 100 };

    expect(validateJsonSchema(100, schema)).toEqual([]);
    expect(validateJsonSchema(101, schema)[0]?.message).toContain('must be <= 100');
    expect(validateJsonSchema(1.5, schema)[0]?.message).toContain('must be integer');
  });

  it('enforces pattern with the unicode flag', () => {
    const schema: JsonSchema = { type: 'string', pattern: '^[a-z]+$' };

    expect(validateJsonSchema('abc', schema)).toEqual([]);
    expect(validateJsonSchema('ABC', schema)[0]?.message).toContain('must match');
  });

  it('resolves $ref against the root $defs', () => {
    const schema: JsonSchema = {
      type: 'object',
      properties: { pkg: { $ref: '#/$defs/name' } },
      $defs: { name: { type: 'string', minLength: 1 } },
    };

    expect(validateJsonSchema({ pkg: 'express' }, schema)).toEqual([]);
    expect(validateJsonSchema({ pkg: '' }, schema)[0]?.path).toBe('/pkg');
  });

  it('reports an unresolved $ref instead of silently passing', () => {
    const schema: JsonSchema = { $ref: '#/$defs/missing' };

    expect(validateJsonSchema({}, schema)[0]?.message).toContain('unresolved $ref');
  });

  it('reports a $ref it cannot resolve rather than guessing', () => {
    const schema: JsonSchema = { $ref: 'https://example.com/other.json' };

    expect(validateJsonSchema({}, schema)[0]?.message).toContain('unsupported $ref');
  });

  it('accepts a value matching at least one anyOf branch', () => {
    const schema: JsonSchema = { anyOf: [{ type: 'null' }, { type: 'number' }] };

    expect(validateJsonSchema(null, schema)).toEqual([]);
    expect(validateJsonSchema(1.5, schema)).toEqual([]);
    expect(validateJsonSchema('x', schema)[0]?.message).toContain('any of the allowed schemas');
  });

  it('rejects a value matching more than one oneOf branch', () => {
    const schema: JsonSchema = {
      oneOf: [{ type: 'number' }, { type: 'integer' }],
    };

    expect(validateJsonSchema(1, schema)[0]?.message).toContain('must match exactly one');
  });

  it('applies every allOf branch', () => {
    const schema: JsonSchema = { allOf: [{ type: 'string' }, { minLength: 3 }] };

    expect(validateJsonSchema('abc', schema)).toEqual([]);
    expect(validateJsonSchema('ab', schema)[0]?.message).toContain('at least 3 characters');
  });

  it('accepts a union type list', () => {
    const schema: JsonSchema = { type: ['string', 'null'] };

    expect(validateJsonSchema(null, schema)).toEqual([]);
    expect(validateJsonSchema('x', schema)).toEqual([]);
    expect(validateJsonSchema(1, schema)[0]?.message).toContain('must be string|null');
  });

  it('rejects non-finite numbers', () => {
    expect(validateJsonSchema(Number.NaN, { type: 'number' })[0]?.message).toContain(
      'must be number',
    );
  });
});

describe('isDeepEqual', () => {
  it('compares primitives', () => {
    expect(isDeepEqual(1, 1)).toBe(true);
    expect(isDeepEqual('a', 'b')).toBe(false);
    expect(isDeepEqual(null, undefined)).toBe(false);
  });

  it('compares arrays order-sensitively', () => {
    expect(isDeepEqual([1, 2], [1, 2])).toBe(true);
    expect(isDeepEqual([1, 2], [2, 1])).toBe(false);
  });

  it('compares nested objects and arrays', () => {
    expect(isDeepEqual({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] })).toBe(true);
    expect(isDeepEqual({ a: [1, { b: 2 }] }, { a: [1, { b: 3 }] })).toBe(false);
  });

  it('treats a missing key as different from an undefined value', () => {
    expect(isDeepEqual({ a: 1 }, { a: 1, b: undefined })).toBe(false);
  });
});
