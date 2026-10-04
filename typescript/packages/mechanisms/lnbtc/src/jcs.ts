/**
 * Serializes a value with the JSON Canonicalization Scheme (RFC 8785).
 *
 * Rejects values outside the I-JSON data model: non-finite numbers, lone
 * surrogates, and non-plain values (undefined, functions, symbols, bigints,
 * class instances).
 *
 * @param value - The value to serialize
 * @returns The canonical JSON text
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("JCS: non-finite number");
      return JSON.stringify(value);
    case "string":
      return serializeString(value);
    case "object":
      if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
      return serializeObject(value as Record<string, unknown>);
    default:
      throw new TypeError(`JCS: unsupported value of type ${typeof value}`);
  }
}

/**
 * Checks a string for lone UTF-16 surrogates.
 *
 * @param value - The string to check
 * @returns Whether every surrogate is paired
 */
export function isWellFormed(value: string): boolean {
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value);
}

/**
 * Serializes a string per ECMAScript JSON.stringify, rejecting lone surrogates.
 *
 * @param value - The string to serialize
 * @returns The quoted, escaped string
 */
function serializeString(value: string): string {
  if (!isWellFormed(value)) throw new TypeError("JCS: invalid Unicode string");
  return JSON.stringify(value);
}

/**
 * Serializes a plain object with members sorted by UTF-16 code units.
 *
 * @param value - The object to serialize
 * @returns The canonical object text
 */
function serializeObject(value: Record<string, unknown>): string {
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError("JCS: only plain objects are supported");
  }
  const keys = Object.keys(value).sort();
  const members = keys.map(key => `${serializeString(key)}:${canonicalize(value[key])}`);
  return `{${members.join(",")}}`;
}
