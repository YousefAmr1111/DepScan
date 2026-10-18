export type JsonSchemaType = 'object' | 'array' | 'string' | 'number' | 'integer' | 'boolean' | 'null';
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
/** Structural equality for JSON values. Used by `const`, `enum` and `uniqueItems`. */
export declare function isDeepEqual(left: unknown, right: unknown): boolean;
/** Validates `value` against `schema`, returning every issue found (empty when valid). */
export declare function validateJsonSchema(value: unknown, schema: JsonSchema): ValidationIssue[];
//# sourceMappingURL=json-schema.d.ts.map