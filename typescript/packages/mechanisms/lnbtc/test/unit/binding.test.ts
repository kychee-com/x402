import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { describe, expect, it } from "vitest";
import {
  bindingsEqual,
  httpRequestBinding,
  mcpToolCallBinding,
  parseBindingExtra,
  type HttpRequestInput,
  type McpToolCallInput,
} from "../../src/binding";
import { canonicalize } from "../../src/jcs";
import { HTTP_A_HASH, HTTP_B_HASH, MCP_A_HASH, httpArticle, mcpArticle } from "./helpers";

const BINDING_ERROR = "invalid_exact_lnbtc_request_binding";

const http = (overrides: Partial<HttpRequestInput> = {}) =>
  httpRequestBinding({
    method: "GET",
    url: "https://api.example.com/article/A",
    boundHeaders: [],
    getHeader: () => undefined,
    ...overrides,
  });

const mcp = (overrides: Partial<McpToolCallInput> = {}) =>
  mcpToolCallBinding({
    server: "https://api.example.com/mcp",
    name: "get_article",
    arguments: { article: "A" },
    boundMetadata: [],
    ...overrides,
  });

describe("canonicalize (RFC 8785)", () => {
  it("sorts members by UTF-16 code units and omits whitespace", () => {
    expect(canonicalize({ b: [1, true, null], a: { d: "x", c: 1.5 } })).toBe(
      '{"a":{"c":1.5,"d":"x"},"b":[1,true,null]}',
    );
    expect(canonicalize({ "€": 1, "\r": 2, "😀": 3 })).toBe('{"\\r":2,"€":1,"😀":3}');
  });

  it("uses ECMAScript string and number serialization", () => {
    expect(canonicalize('a\n"\\\u0001')).toBe('"a\\n\\"\\\\\\u0001"');
    expect(canonicalize(1e21)).toBe("1e+21");
    expect(canonicalize(-0)).toBe("0");
    expect(canonicalize(0.000001)).toBe("0.000001");
  });

  it("rejects values outside the data model", () => {
    expect(() => canonicalize(Number.NaN)).toThrow();
    expect(() => canonicalize(Infinity)).toThrow();
    expect(() => canonicalize("\ud800")).toThrow();
    expect(() => canonicalize({ ["\udc00"]: 1 })).toThrow();
    expect(() => canonicalize(undefined)).toThrow();
    expect(() => canonicalize(1n)).toThrow();
    expect(() => canonicalize(new Date(0))).toThrow();
    expect(canonicalize(Object.create(null))).toBe("{}");
  });
});

describe("http:1 binding", () => {
  it("matches the specification vectors", () => {
    expect(httpArticle("A").requestHash).toBe(HTTP_A_HASH);
    expect(httpArticle("B").requestHash).toBe(HTTP_B_HASH);
    expect(httpArticle().resourceUrl).toBe("https://api.example.com/article/A");
    expect(httpArticle().requestBindingParams).toEqual({ headers: [] });
  });

  it("binds method case, raw body bytes, and URL spelling", () => {
    const hashes = new Set([
      http().requestHash,
      http({ method: "get" }).requestHash,
      http({ method: "POST" }).requestHash,
      http({ body: new TextEncoder().encode('{"a":1}') }).requestHash,
      http({ body: new TextEncoder().encode('{"a": 1}') }).requestHash,
      http({ url: "https://api.example.com/article/%41" }).requestHash,
      http({ url: "https://api.example.com/article/A?x=1&y=2" }).requestHash,
      http({ url: "https://api.example.com/article/A?y=2&x=1" }).requestHash,
    ]);
    expect(hashes.size).toBe(8);
    expect(http({ body: new Uint8Array() }).requestHash).toBe(HTTP_A_HASH);
  });

  it("distinguishes absent, empty, and present headers and trims field values", () => {
    const withHeader = (value: string | string[] | undefined) =>
      http({ boundHeaders: ["accept"], getHeader: () => value }).requestHash;
    expect(new Set([withHeader(undefined), withHeader(""), withHeader("x")]).size).toBe(3);
    expect(withHeader("  text/plain\t")).toBe(withHeader("text/plain"));
    expect(withHeader(["a", " b"])).toBe(withHeader("a, b"));
  });

  it("rejects malformed inputs", () => {
    const bad: Partial<HttpRequestInput>[] = [
      { method: "GE T" },
      { method: "" },
      { url: "https://api.example.com/a#frag" },
      { url: "https://user:pw@api.example.com/a" },
      { url: "https://user@api.example.com/a" },
      { url: "ftp://api.example.com/a" },
      { url: "/relative" },
      { url: "https://api.example.com/café" },
      { boundHeaders: ["Accept"] },
      { boundHeaders: ["b", "a"] },
      { boundHeaders: ["a", "a"] },
      { boundHeaders: ["payment-signature"] },
      { boundHeaders: ["accept"], getHeader: () => "café" },
    ];
    for (const input of bad)
      expect(() => http(input), JSON.stringify(input)).toThrow(BINDING_ERROR);
  });
});

describe("mcp:1 binding", () => {
  it("matches the specification vectors", () => {
    expect(mcpArticle("A").requestHash).toBe(MCP_A_HASH);
    expect(mcp({ arguments: { article: "B" } }).requestHash).toBe(
      "b3e425970d64cd4f08fc4d57a11b76da59ce6a5760d92687398c91f063120678",
    );
    expect(mcp({ name: "delete_article" }).requestHash).toBe(
      "3a52bbf19dda8b5765a27246b12e805770298273b48526956c421f02fe043455",
    );
    expect(mcp({ server: "https://other.example.com/mcp" }).requestHash).toBe(
      "96903c29186c6aabc95e48abafd8ce3ad32b4060f5d5bf22cf75f3fbfe816e45",
    );
    expect(mcpArticle().resourceUrl).toBeUndefined();
  });

  it("hashes absent and null metadata as the specification vectors", () => {
    expect(bytesToHex(sha256(Uint8Array.of(0)))).toBe(
      "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    );
    expect(bytesToHex(sha256(new TextEncoder().encode("\u0001null")))).toBe(
      "c58dcb77cee9027d1f4b3207bd876d232e61f79ee9f9dbd4e6d834778da78b16",
    );
    const absent = mcp({ boundMetadata: ["tier"], meta: {} }).requestHash;
    const nul = mcp({ boundMetadata: ["tier"], meta: { tier: null } }).requestHash;
    const value = mcp({ boundMetadata: ["tier"], meta: { tier: { b: 1, a: 2 } } }).requestHash;
    expect(new Set([absent, nul, value]).size).toBe(3);
    expect(mcp({ boundMetadata: ["tier"], meta: { tier: { a: 2, b: 1 } } }).requestHash).toBe(
      value,
    );
  });

  it("treats omitted arguments and meta as empty objects and ignores unbound metadata", () => {
    expect(mcp({ arguments: undefined }).requestHash).toBe(mcp({ arguments: {} }).requestHash);
    expect(mcp({ meta: { progressToken: 7, "x402/payment": {} } }).requestHash).toBe(MCP_A_HASH);
  });

  it("rejects malformed inputs", () => {
    const bad: Partial<McpToolCallInput>[] = [
      { name: "" },
      { arguments: null },
      { arguments: [] },
      { arguments: "x" },
      { meta: null },
      { meta: [] },
      { server: "https://api.example.com/mcp#x" },
      { server: "not a uri" },
      { boundMetadata: [""] },
      { boundMetadata: ["b", "a"] },
      { boundMetadata: ["x402/payment"] },
      { boundMetadata: ["progressToken"] },
      { arguments: { bad: Number.NaN } },
    ];
    for (const input of bad) expect(() => mcp(input), JSON.stringify(input)).toThrow(BINDING_ERROR);
  });
});

describe("parseBindingExtra and bindingsEqual", () => {
  it("accepts valid extras and compares parameters by JCS", () => {
    const a = parseBindingExtra({ ...httpArticle(), extraField: 1 });
    expect(a.requestHash).toBe(HTTP_A_HASH);
    const m1 = parseBindingExtra(mcpArticle());
    const m2 = parseBindingExtra({
      ...mcpArticle(),
      requestBindingParams: { metadata: [], server: "https://api.example.com/mcp" },
    });
    expect(bindingsEqual(m1, m2)).toBe(true);
    expect(bindingsEqual(a, m1)).toBe(false);
  });

  it("rejects missing, unknown, or malformed binding fields", () => {
    const base = httpArticle();
    const bad = [
      undefined,
      { ...base, requestHash: undefined },
      { ...base, requestHash: base.requestHash.toUpperCase() },
      { ...base, requestBindingProfile: "http:2" },
      { ...base, requestBindingProfile: undefined },
      { ...base, requestBindingParams: undefined },
      { ...base, requestBindingParams: [] },
      { ...base, requestBindingParams: {} },
      { ...base, requestBindingParams: { headers: [], extra: 1 } },
      { ...mcpArticle(), requestBindingParams: { server: "https://a.example/mcp" } },
      { ...mcpArticle(), requestBindingParams: { server: 1, metadata: [] } },
      { ...mcpArticle(), requestBindingParams: { server: "https://a.example/mcp", metadata: "" } },
    ];
    for (const extra of bad) {
      expect(() => parseBindingExtra(extra as Record<string, unknown>)).toThrow(BINDING_ERROR);
    }
  });
});
