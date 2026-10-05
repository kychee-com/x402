/**
 * Cross-SDK parity with the Python `lnbtc` mechanism (x402-foundation/x402
 * PR #1873, commit 2d85314c42fab607395c78cb09ecc926110252ff).
 *
 * Every Python test case from `python/x402/tests/unit/mechanisms/lnbtc/`
 * (`test_binding.py`, `test_settlement.py`, `test_sdk.py`) is ported here, with
 * the Python test name in the title. Python-only behavior (SQLite files,
 * sync/async SDK pairs, Flask) is mapped to its closest TypeScript analog.
 *
 * Titles starting with `DIVERGENCE` pin a TypeScript result that differs from
 * the Python one; the comment next to each states which side the merged
 * specification supports. A later Python commit, d162e678 (authority header
 * validation), is ported in its own block; it changes no published vector.
 */
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { bech32 } from "@scure/base";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { x402Facilitator } from "@x402/core/facilitator";
import {
  type FacilitatorClient,
  type HTTPAdapter,
  type HTTPResponseInstructions,
  x402HTTPResourceServer,
  x402ResourceServer,
} from "@x402/core/server";
import { encodePaymentSignatureHeader, type HTTPTransportContext } from "@x402/core/http";
import type {
  Network,
  PaymentPayload,
  PaymentRequired,
  PaymentRequirements,
  SchemePaymentRequiredContext,
  SettleResponse,
  SupportedResponse,
} from "@x402/core/types";
import { describe, expect, it, vi } from "vitest";
import {
  httpRequestBinding,
  mcpToolCallBinding,
  type HttpRequestInput,
  type McpToolCallInput,
  type RequestBinding,
} from "../../src/binding";
import { decodeInvoice } from "../../src/bolt11";
import { LNBTC_MAINNET, LNBTC_TESTNET } from "../../src/constants";
import { ExactLnbtcScheme as LnbtcClient } from "../../src/exact/client";
import { ExactLnbtcScheme as LnbtcFacilitator } from "../../src/exact/facilitator";
import { ExactLnbtcScheme as LnbtcServer, httpTransportBinding } from "../../src/exact/server";
import { InMemoryReplayStore } from "../../src/replayStore";
import type {
  CreateInvoiceParams,
  LightningPayer,
  LightningPayment,
  LightningReceiver,
  ReplayStore,
} from "../../src/types";
import { RECEIVER_PUBKEY, makeInvoice } from "./helpers";

// ---------------------------------------------------------------------------
// Ports of python/x402/tests/unit/mechanisms/lnbtc/helpers.py
// ---------------------------------------------------------------------------

const NOW = 1_700_000_000;
const KEY = hexToBytes("0".repeat(63) + "1");
const PAYEE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const PREIMAGE = "42".repeat(32);
const URL_A = "https://api.example.com/article/A";
const ORIGIN = "https://api.example.com";
const MCP_SERVER = "https://api.example.com/mcp";

interface PyInvoiceOptions {
  preimage?: string;
  amount?: number;
  expiry?: number;
  date?: number;
  currency?: string;
  key?: Uint8Array;
  inlineDescription?: boolean;
}

// helpers.invoice: p, s ("23" * 32), x, then h (or d = "test"), signed by KEY.
const pyInvoice = (digest: string, options: PyInvoiceOptions = {}): string =>
  makeInvoice({
    preimage: options.preimage ?? PREIMAGE,
    paymentSecret: "23".repeat(32),
    amountMsat: BigInt(options.amount ?? 21000),
    expiry: options.expiry ?? 300,
    timestamp: options.date ?? NOW,
    currency: options.currency ?? "bc",
    key: options.key ?? KEY,
    descriptionHash: options.inlineDescription ? null : digest,
    description: options.inlineDescription ? "test" : undefined,
  }).invoice;

// helpers.Receiver: preimage = sha256(str(n)) for the n-th invoice.
const pyReceiver = () => {
  const preimages = new Map<string, string>();
  const receiver: LightningReceiver & { preimages: Map<string, string> } = {
    preimages,
    createInvoice: vi.fn(async (params: CreateInvoiceParams) => {
      const preimage = bytesToHex(sha256(new TextEncoder().encode(String(preimages.size))));
      const invoice = pyInvoice(params.descriptionHash, {
        preimage,
        amount: Number(params.amountMsat),
        expiry: params.expirySeconds,
        currency: params.network === LNBTC_TESTNET ? "tb" : "bc",
      });
      preimages.set(invoice, preimage);
      return invoice;
    }),
  };
  return receiver;
};

// helpers.Payer: reports the decoded invoice as paid, with optional overrides.
const pyPayer = (
  receiver?: ReturnType<typeof pyReceiver>,
  overrides: Partial<LightningPayment> = {},
) => {
  const payer: LightningPayer = {
    payInvoice: vi.fn(async (invoice: string) => {
      const decoded = decodeInvoice(invoice);
      return {
        invoice,
        paymentHash: decoded.paymentHash,
        amountMsat: decoded.amountMsat,
        status: "paid" as const,
        preimage: receiver ? receiver.preimages.get(invoice) : PREIMAGE,
        ...overrides,
      };
    }),
  };
  return payer;
};

// Python header lists are (name, value) pairs; the TypeScript input is a
// lookup by lowercase name returning every field line.
const headerLookup = (pairs: [string, string][]): HttpRequestInput["getHeader"] => {
  return name => {
    const values = pairs.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v);
    return values.length === 0 ? undefined : values;
  };
};

// test_binding.http / http_request_binding("GET", URL, public_origin=...).
const http = (
  options: {
    method?: string;
    url?: string;
    body?: unknown;
    headers?: [string, string][];
    boundHeaders?: string[];
  } = {},
) =>
  httpRequestBinding({
    method: options.method ?? "GET",
    url: options.url ?? URL_A,
    body: options.body as Uint8Array | undefined,
    boundHeaders: options.boundHeaders ?? [],
    getHeader: headerLookup(options.headers ?? []),
  });

// test_binding.mcp: params default to {"name": "get_article"}.
const mcp = (params: Record<string, unknown> = { name: "get_article" }, metadata: string[] = []) =>
  mcpToolCallBinding({
    server: MCP_SERVER,
    name: params.name as string,
    arguments: "arguments" in params ? params.arguments : undefined,
    meta: "_meta" in params ? params._meta : undefined,
    boundMetadata: metadata,
  } as McpToolCallInput);

const extraOf = (binding: RequestBinding) => ({
  requestHash: binding.requestHash,
  requestBindingProfile: binding.requestBindingProfile,
  requestBindingParams: binding.requestBindingParams,
});

// Verbatim spec_http.json (the public JSON examples of the specification).
const SPEC_HTTP = {
  requirements: {
    scheme: "exact",
    network: "lnbtc:000000000019d6689c085ae165831e93",
    amount: "25000",
    asset: "BTC",
    payTo: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    maxTimeoutSeconds: 300,
    extra: {
      assetTransferMethod: "bolt11",
      paymentFlow: "upfront",
      requestHash: "0d6623f775e025501fa7f0a30b54da25aad62b6ccfe35c85da38016711e6c018",
      requestBindingProfile: "http:1",
      requestBindingParams: { headers: [] },
      invoice:
        "lnbc250n1pj48ugqpp54y3u9s8ylemsv8l3ewyzzu0klhujvuvmkl6llchq23vy8rzjsf0qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp5p4nz8am4uqj4q8a87z3sk4x6yk4dv2mvel34epw68qqkwy0xcqvqxqzfvcqpjr4rx6ls6j5rpwknuea64evlk7yfx56wmqcer5eerekdsn9tlv6v4ex9mlz5dtm9qapl3svwlqcf7837dmjkru9z9w4h2rvm0md52w2sqxrwu5f",
    },
  },
  payload: {
    x402Version: 2,
    accepted: {
      scheme: "exact",
      network: "lnbtc:000000000019d6689c085ae165831e93",
      amount: "25000",
      asset: "BTC",
      payTo: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      maxTimeoutSeconds: 300,
      extra: {
        assetTransferMethod: "bolt11",
        paymentFlow: "upfront",
        requestHash: "0d6623f775e025501fa7f0a30b54da25aad62b6ccfe35c85da38016711e6c018",
        requestBindingProfile: "http:1",
        requestBindingParams: { headers: [] },
        invoice:
          "lnbc250n1pj48ugqpp54y3u9s8ylemsv8l3ewyzzu0klhujvuvmkl6llchq23vy8rzjsf0qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp5p4nz8am4uqj4q8a87z3sk4x6yk4dv2mvel34epw68qqkwy0xcqvqxqzfvcqpjr4rx6ls6j5rpwknuea64evlk7yfx56wmqcer5eerekdsn9tlv6v4ex9mlz5dtm9qapl3svwlqcf7837dmjkru9z9w4h2rvm0md52w2sqxrwu5f",
      },
    },
    payload: {
      preimage: "0001020304050607080900010203040506070809000102030405060708090102",
    },
  },
};

// test_settlement fixture `proof`: fresh copies of the verbatim vector.
const proof = (): [PaymentPayload, PaymentRequirements] => {
  const vector = structuredClone(SPEC_HTTP);
  return [vector.payload as PaymentPayload, vector.requirements as PaymentRequirements];
};

// test_settlement fixture `facilitator`: a fresh durable store, clock NOW.
const pyFacilitator = (now = NOW, store: ReplayStore = new InMemoryReplayStore()) =>
  new LnbtcFacilitator({ replayStore: store, clock: () => now });

const local = (facilitator: x402Facilitator): FacilitatorClient => ({
  verify: (p, r) => facilitator.verify(p, r),
  settle: (p, r) => facilitator.settle(p, r),
  getSupported: () => Promise.resolve(facilitator.getSupported() as SupportedResponse),
});

// test_sdk.sdk_client: BTC allowed on both networks up to 25000 msat.
const sdkClient = () =>
  new x402Client().setSpendControls({
    allowedAssets: [LNBTC_MAINNET, LNBTC_TESTNET].map(network => ({
      network,
      asset: "BTC",
      maxAmountPerPayment: "25000",
    })),
  });

// ---------------------------------------------------------------------------
// test_binding.py
// ---------------------------------------------------------------------------

describe("python parity: test_binding.py", () => {
  it("test_published_http_vectors", () => {
    expect(http().requestHash).toBe(
      "0d6623f775e025501fa7f0a30b54da25aad62b6ccfe35c85da38016711e6c018",
    );
    expect(http({ url: URL_A.slice(0, -1) + "B" }).requestHash).toBe(
      "4a99860f75eed1ea8178a5db488e044173bc570c8a6210f2c8590cdf8622d509",
    );
  });

  it.each([
    [
      "get_article",
      { article: "A" },
      "03941bfedc6af8a09b2f459fe83470284a76a8c75801caa9e1487a9276a693f4",
    ],
    [
      "get_article",
      { article: "B" },
      "b3e425970d64cd4f08fc4d57a11b76da59ce6a5760d92687398c91f063120678",
    ],
    [
      "delete_article",
      { article: "A" },
      "3a52bbf19dda8b5765a27246b12e805770298273b48526956c421f02fe043455",
    ],
  ])("test_published_mcp_vectors[%s-%o]", (name, args, digest) => {
    expect(mcp({ name, arguments: args }).requestHash).toBe(digest);
  });

  it("test_raw_http_bytes_and_target_spelling_are_not_normalized", () => {
    const bytes = (text: string) => new TextEncoder().encode(text);
    expect(http({ body: bytes('{"a":1}') }).requestHash).not.toBe(
      http({ body: bytes('{"a": 1}') }).requestHash,
    );
    expect(http({ method: "get" }).requestHash).not.toBe(http().requestHash);
    const hashes = new Set(
      ["%2f", "%2F", "?a=1&b=2", "?b=2&a=1"].map(
        path => http({ url: `https://api.example.com/${path}` }).requestHash,
      ),
    );
    expect(hashes.size).toBe(4);
  });

  it("test_bound_header_absence_empty_and_repeated_values", () => {
    expect(http({ boundHeaders: ["cookie"] }).requestHash).not.toBe(
      http({ boundHeaders: ["cookie"], headers: [["cookie", ""]] }).requestHash,
    );
    expect(
      http({
        boundHeaders: ["cookie"],
        headers: [
          ["Cookie", " a "],
          ["COOKIE", "\tb\t"],
        ],
      }).requestHash,
    ).toBe(http({ boundHeaders: ["cookie"], headers: [["cookie", "a, b"]] }).requestHash);
  });

  it.each([
    [{ boundHeaders: ["Cookie"] }],
    [{ boundHeaders: ["z", "a"] }],
    [{ boundHeaders: ["a", "a"] }],
    [{ boundHeaders: ["payment-signature"] }],
    [{ boundHeaders: ["a"], headers: [["a", "bad\r\nvalue"]] as [string, string][] }],
    [{ boundHeaders: ["a"], headers: [["a", "é"]] as [string, string][] }],
    // Python passes a str body; the TypeScript analog is a non-bytes body.
    [{ body: "parsed" }],
  ])("test_invalid_http_inputs_fail_closed[%o]", options => {
    expect(() => http(options)).toThrow("invalid_exact_lnbtc_request_binding");
  });

  it.each([
    "/article/A",
    "https://user:pass@api.example.com/a",
    `${URL_A}#fragment`,
    `${URL_A}%zz`,
    "https://api.example.com/é",
  ])("test_unsafe_uri_or_untrusted_origin[%s]", url => {
    expect(() => http({ url })).toThrow("invalid_exact_lnbtc_request_binding");
  });

  // Python: http_request_binding("GET", "https://evil.example/a",
  // public_origin="https://api.example.com") raises request_mismatch.
  // TypeScript has no origin argument on httpRequestBinding: the server's
  // httpTransportBinding never takes the origin from the request at all, it
  // hashes the configured publicOrigin plus the request target. A request that
  // arrived for evil.example is therefore bound as api.example.com, not
  // refused. Both keep the hashed origin out of the requester's control; the
  // spec's "validate the public origin against its configuration" reads
  // closer to Python's explicit refusal. Reported as a design difference.
  it("DIVERGENCE test_unsafe_uri_or_untrusted_origin[https://evil.example/a]: TypeScript binds the configured origin instead of refusing", async () => {
    expect(() => http({ url: "https://evil.example/a" })).not.toThrow();
    const binding = await httpTransportBinding({ publicOrigin: ORIGIN })({
      request: {
        adapter: {
          getMethod: () => "GET",
          getUrl: () => "https://evil.example/a",
          getHeader: (name: string) => (name === "host" ? "evil.example" : undefined),
        },
      },
    } as unknown as HTTPTransportContext);
    expect(binding.resourceUrl).toBe("https://api.example.com/a");
    expect(binding.requestHash).toBe(http({ url: "https://api.example.com/a" }).requestHash);
  });

  it("test_mcp_canonical_arguments_and_nonbinding_metadata", () => {
    const first = mcp({ name: "get_article", arguments: { b: 2, a: 1 } });
    const retry = mcp({
      name: "get_article",
      arguments: { a: 1, b: 2 },
      _meta: { progressToken: "new", "x402/payment": { preimage: "proof" } },
    });
    expect(first.requestHash).toBe(retry.requestHash);
    expect(mcp().requestHash).toBe(mcp({ name: "get_article", arguments: {} }).requestHash);
    expect(mcp(undefined, ["account"]).requestHash).not.toBe(
      mcp({ name: "get_article", _meta: { account: null } }, ["account"]).requestHash,
    );
  });

  it.each([
    [{ name: "get_article", arguments: null }, []],
    [{ name: "get_article", arguments: [] }, []],
    [{ name: "get_article", _meta: null }, []],
    [{ name: "get_article", arguments: { x: NaN } }, []],
    // Python's 2**64 is an arbitrary-precision int; the TypeScript analog is a bigint.
    [{ name: "get_article", arguments: { x: 2n ** 64n } }, []],
    [{ name: "get_article", arguments: { x: "\ud800" } }, []],
    [{ name: "get_article" }, ["progressToken"]],
    [{ name: "get_article" }, ["x402/payment"]],
    [{ name: "get_article" }, ["z", "a"]],
  ])("test_invalid_mcp_inputs_fail_closed[%o-%o]", (params, metadata) => {
    expect(() => mcp(params, metadata)).toThrow("invalid_exact_lnbtc_request_binding");
  });

  // Python rejects the int 2**64 because RFC 8785 libraries refuse integers
  // outside the IEEE-754 exact range. A JavaScript JSON.parse of the same
  // JSON-RPC text yields the double 2^64, which JCS serializes as
  // 18446744073709552000, so TypeScript binds it (and binds 2^64 + 1, which
  // parses to the same double, identically). Both fail closed across SDKs (the
  // side that rejects never issues or pays), but they disagree on whether such
  // a call is bindable. The spec says "reject inputs outside [JCS's] data
  // model" without saying whether integers beyond 2^53 are inside it.
  it("DIVERGENCE test_invalid_mcp_inputs_fail_closed[2**64]: a JSON number 2^64 is bindable in TypeScript", () => {
    const parsed = JSON.parse('{"x":18446744073709551616}') as Record<string, unknown>;
    const binding = mcp({ name: "get_article", arguments: parsed });
    expect(binding.requestHash).toMatch(/^[0-9a-f]{64}$/);
    const plusOne = JSON.parse('{"x":18446744073709551617}') as Record<string, unknown>;
    expect(mcp({ name: "get_article", arguments: plusOne }).requestHash).toBe(binding.requestHash);
  });
});

// ---------------------------------------------------------------------------
// test_settlement.py
// ---------------------------------------------------------------------------

describe("python parity: test_settlement.py", () => {
  it("test_spec_proof_settles_without_node_access_and_omits_payer", async () => {
    const facilitator = pyFacilitator();
    const result = await facilitator.settle(...proof());
    expect(result).toEqual({
      success: true,
      transaction: "a923c2c0e4fe77061ff1cb882171f6fdf926719bb7f5ffe2e05458438c52825e",
      network: LNBTC_MAINNET,
    });
    expect(result).not.toHaveProperty("payer");
    expect((await facilitator.settle(...proof())).errorReason).toBe("duplicate_settlement");
  });

  it("test_fresh_challenge_does_not_replace_accepted_invoice", async () => {
    const [payload, requirements] = proof();
    requirements.extra.invoice = pyInvoice(requirements.extra.requestHash as string, {
      amount: Number(requirements.amount),
    });
    expect(requirements.extra.invoice).not.toBe(payload.accepted.extra.invoice);
    expect((await pyFacilitator().settle(payload, requirements)).success).toBe(true);
  });

  it.each([
    ["scheme", "other", "unsupported_scheme"],
    ["network", LNBTC_TESTNET, "network_mismatch"],
    ["asset", "btc", "invalid_exact_lnbtc_asset"],
    ["amount", "1", "invalid_exact_lnbtc_amount_mismatch"],
    ["payTo", "bad", "invalid_exact_lnbtc_pay_to_mismatch"],
    ["maxTimeoutSeconds", 1, "invalid_exact_lnbtc_max_timeout_mismatch"],
  ])("test_mismatched_terms[%s-%o]", async (field, value, reason) => {
    const [payload, requirements] = proof();
    (payload.accepted as unknown as Record<string, unknown>)[field] = value;
    expect((await pyFacilitator().settle(payload, requirements)).errorReason).toBe(reason);
  });

  // Python returns invalid_exact_lnbtc_amount: match_requirements validates
  // both amounts as positive integers before comparing them. The spec runs
  // step 1 (accepted.amount equals requirements.amount) before step 2
  // (positive integral amount), so the first failing check is the mismatch.
  // TypeScript follows the step order. The error table's "Either amount is
  // not a positive integer" wording is what invites Python's reading.
  it("DIVERGENCE test_mismatched_terms[amount-0]: TypeScript reports the step-1 mismatch", async () => {
    const [payload, requirements] = proof();
    payload.accepted.amount = "0";
    expect((await pyFacilitator().settle(payload, requirements)).errorReason).toBe(
      "invalid_exact_lnbtc_amount_mismatch",
    );
  });

  it.each([
    ["requestHash", null, "request_binding"],
    ["requestBindingProfile", "unknown", "request_binding"],
    ["requestBindingParams", { headers: [], unknown: true }, "request_binding"],
    ["requestBindingParams", { headers: ["accept"] }, "request_mismatch"],
    ["assetTransferMethod", "other", "asset_transfer_method"],
    ["paymentFlow", null, "payment_flow"],
    ["invoice", "", "invoice_missing"],
    ["invoice", "garbage", "invoice_decode_failed"],
  ])("test_untrusted_extra[%s-%o]", async (field, value, reason) => {
    const [payload, requirements] = proof();
    payload.accepted.extra[field] = value;
    expect((await pyFacilitator().settle(payload, requirements)).errorReason).toBe(
      `invalid_exact_lnbtc_${reason}`,
    );
  });

  it("test_defaults_and_additive_client_fields", async () => {
    const [payload, requirements] = proof();
    delete payload.accepted.extra.assetTransferMethod;
    payload.accepted.extra.clientNote = "ignored";
    expect((await pyFacilitator().settle(payload, requirements)).success).toBe(true);
  });

  it("test_server_declared_extra_is_not_ignored", async () => {
    const [payload, requirements] = proof();
    requirements.extra.merchant = "expected";
    expect((await pyFacilitator().settle(payload, requirements)).errorReason).toBe(
      "invalid_exact_lnbtc_extra_mismatch",
    );
  });

  it.each([false, true])("test_article_substitution[echo=%s]", async echo => {
    const [payload, requirements] = proof();
    const binding = http({ url: "https://api.example.com/article/B" });
    Object.assign(requirements.extra, extraOf(binding));
    if (echo) Object.assign(payload.accepted.extra, extraOf(binding));
    const expected = echo ? "invoice_request_mismatch" : "request_mismatch";
    expect((await pyFacilitator().settle(payload, requirements)).errorReason).toBe(
      `invalid_exact_lnbtc_${expected}`,
    );
  });

  it.each([
    [{ inlineDescription: true }, "invoice_description"],
    [{ key: hexToBytes("2".repeat(64)) }, "invoice_payee_mismatch"],
    [{ currency: "tb" }, "invoice_currency_mismatch"],
    [{ amount: 1 }, "invoice_amount_mismatch"],
    [{ expiry: 1 }, "invoice_expiry_mismatch"],
    [{ date: NOW + 61 }, "invoice_created_in_future"],
  ])("test_signed_invoice_mismatches[%o]", async (options: PyInvoiceOptions, reason) => {
    const [payload, requirements] = proof();
    payload.accepted.extra.invoice = pyInvoice(requirements.extra.requestHash as string, {
      amount: Number(requirements.amount),
      ...options,
    });
    payload.payload.preimage = PREIMAGE;
    expect((await pyFacilitator().settle(payload, requirements)).errorReason).toBe(
      `invalid_exact_lnbtc_${reason}`,
    );
  });

  it("test_invoice_created_at_clock_skew_boundary_is_valid", async () => {
    const [payload, requirements] = proof();
    payload.accepted.extra.invoice = pyInvoice(requirements.extra.requestHash as string, {
      amount: Number(requirements.amount),
      date: NOW + 60,
    });
    payload.payload.preimage = PREIMAGE;
    expect((await pyFacilitator().settle(payload, requirements)).success).toBe(true);
  });

  it.each([
    [null, "preimage_missing"],
    ["ABC", "preimage_malformed"],
    ["a".repeat(63), "preimage_length"],
    ["00".repeat(32), "preimage_hash_mismatch"],
  ])("test_bad_proof_does_not_consume_invoice[%o]", async (preimage, reason) => {
    const facilitator = pyFacilitator();
    const [payload, requirements] = proof();
    const original = payload.payload.preimage;
    payload.payload.preimage = preimage;
    expect((await facilitator.settle(payload, requirements)).errorReason).toBe(
      `invalid_exact_lnbtc_${reason}`,
    );
    payload.payload.preimage = original;
    expect((await facilitator.settle(payload, requirements)).success).toBe(true);
  });

  it.each([
    [300, true],
    [360, true],
    [361, false],
  ])("test_paid_expiry_boundary[%d-%s]", async (offset, success) => {
    const result = await pyFacilitator(NOW + offset).settle(...proof());
    expect(result.success).toBe(success);
    if (!success) expect(result.errorReason).toBe("invalid_exact_lnbtc_invoice_expired");
  });

  // Python: twelve facilitator instances on one SQLite file, a thirteenth
  // "restarted" instance, and a read of the stored row. TypeScript ships no
  // durable store (InMemoryReplayStore is documented as test-only); the
  // analog shares one store across instances and records the inserted row.
  it("test_concurrent_instances_restart_and_retention", async () => {
    const shared = new InMemoryReplayStore();
    const rows: [string, number][] = [];
    const store: ReplayStore = {
      consume: async (key, retainUntil) => {
        const inserted = await shared.consume(key, retainUntil);
        if (inserted) rows.push([key, retainUntil]);
        return inserted;
      },
    };
    const instances = Array.from({ length: 12 }, () => pyFacilitator(NOW, store));
    const results = await Promise.all(instances.map(f => f.settle(...proof())));
    expect(results.filter(r => r.success)).toHaveLength(1);
    expect(results.filter(r => r.errorReason === "duplicate_settlement")).toHaveLength(11);
    const restarted = pyFacilitator(NOW, store);
    expect((await restarted.settle(...proof())).errorReason).toBe("duplicate_settlement");
    const winner = results.find(r => r.success)!;
    expect(rows).toEqual([[`${LNBTC_MAINNET}:${winner.transaction}`, NOW + 300 + 60 + 3600]]);
  });

  // Known, documented difference: Python returns settlement_failed, TypeScript
  // propagates the store error. Both deny the handler and consume nothing
  // (spec PR #3698 proposes exact_lnbtc_replay_store_unavailable).
  it("test_store_failure_cannot_grant_access (known: TypeScript throws instead of settlement_failed)", async () => {
    const broken: ReplayStore = {
      consume: async () => {
        throw new Error("unavailable");
      },
    };
    await expect(pyFacilitator(NOW, broken).settle(...proof())).rejects.toThrow("unavailable");
  });

  it("test_verify_never_consumes", async () => {
    const facilitator = pyFacilitator();
    expect((await facilitator.verify(...proof())).isValid).toBe(false);
    expect((await facilitator.settle(...proof())).success).toBe(true);
  });

  // test_nonpersistent_sqlite_rejected: not applicable. TypeScript provides
  // only the ReplayStore interface and a test-only in-memory store; there is
  // no SQLite store whose path could be validated.

  it.each(["mixed-case", "checksum", "duplicate-h", "padding", "fractional-msat"])(
    "test_strict_bolt11_rejections[%s]",
    async mutation => {
      const [payload, requirements] = proof();
      const original = payload.accepted.extra.invoice as string;
      const { prefix, words } = bech32.decode(original as `${string}1${string}`, false);
      const encode = (hrp: string, data: number[]) => bech32.encode(hrp, data, false);
      let modified: string;
      if (mutation === "mixed-case") {
        modified = original.slice(0, 4).toUpperCase() + original.slice(4);
      } else if (mutation === "checksum") {
        modified = original.slice(0, -1) + (original.at(-1) !== "q" ? "q" : "p");
      } else if (mutation === "fractional-msat") {
        modified = encode("lnbc11p", words);
      } else if (mutation === "duplicate-h") {
        // A second 52-word h field, preserving the Bech32 checksum.
        const h = [23, 1, 20, ...new Array<number>(52).fill(0)];
        modified = encode(prefix, [...words.slice(0, -104), ...h, ...words.slice(-104)]);
      } else {
        // Non-zero padding in the last word of the p field.
        const padded = [...words];
        padded[61] |= 1;
        modified = encode(prefix, padded);
      }
      payload.accepted.extra.invoice = modified;
      const expected = mutation === "duplicate-h" ? "invoice_description" : "invoice_decode_failed";
      expect((await pyFacilitator().settle(payload, requirements)).errorReason).toBe(
        `invalid_exact_lnbtc_${expected}`,
      );
    },
  );

  it("test_same_hash_has_separate_consumption_on_each_network", async () => {
    const facilitator = pyFacilitator();
    const [payload, requirements] = proof();
    for (const [network, currency] of [
      [LNBTC_MAINNET, "bc"],
      [LNBTC_TESTNET, "tb"],
    ] as const) {
      payload.accepted.network = requirements.network = network;
      const value = pyInvoice(requirements.extra.requestHash as string, {
        amount: Number(requirements.amount),
        currency,
      });
      payload.accepted.extra.invoice = requirements.extra.invoice = value;
      payload.payload.preimage = PREIMAGE;
      expect((await facilitator.settle(payload, requirements)).success).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// test_sdk.py
// ---------------------------------------------------------------------------

describe("python parity: test_sdk.py", () => {
  const binding = () => http();
  // test_sdk.requirement: 21000 msat, no explicit transfer method.
  const requirement = (): PaymentRequirements => ({
    scheme: "exact",
    network: LNBTC_MAINNET,
    asset: "BTC",
    amount: "21000",
    payTo: PAYEE,
    maxTimeoutSeconds: 300,
    extra: {
      ...extraOf(binding()),
      paymentFlow: "upfront",
      invoice: pyInvoice(binding().requestHash),
    },
  });
  const challenge = (requirements: PaymentRequirements, url = URL_A): PaymentRequired => ({
    x402Version: 2,
    resource: { url },
    accepts: [requirements],
  });

  it("uses the same test payee as the TypeScript helpers", () => {
    expect(PAYEE).toBe(RECEIVER_PUBKEY);
  });

  it.each([
    [{ invoice: "other" }, "payer_invoice_mismatch"],
    [{ paymentHash: "00".repeat(32) }, "payer_payment_hash_mismatch"],
    [{ amountMsat: 21001n }, "payer_amount_mismatch"],
    [{ preimage: null as unknown as string }, "payer_preimage_required"],
    [{ preimage: "FF".repeat(32) }, "payer_preimage_malformed"],
    [{ preimage: "00".repeat(32) }, "payer_preimage_hash_mismatch"],
    [{ status: "unpaid" as const }, "payment_not_paid"],
    [{ status: "in_flight" as const }, "payment_in_flight"],
  ])("test_payer_cannot_report_unproven_or_different_payment[%o]", async (overrides, reason) => {
    const payer = pyPayer(undefined, overrides);
    const client = new LnbtcClient({ payer, requestBinding: binding, clock: () => NOW });
    await expect(client.createPaymentPayload(2, requirement())).rejects.toThrow(reason);
    expect(payer.payInvoice).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["digest", "invalid_exact_lnbtc_request_mismatch"],
    ["resource", "invalid_exact_lnbtc_request_mismatch"],
    ["profile", "invalid_exact_lnbtc_request_mismatch"],
    ["expired", "invalid_exact_lnbtc_invoice_expired"],
  ])("test_client_checks_challenge_before_paying[%s]", async (change, reason) => {
    const payer = pyPayer();
    const client = sdkClient().register(
      LNBTC_MAINNET,
      new LnbtcClient({ payer, requestBinding: binding, clock: () => NOW }),
    );
    const requirements = requirement();
    let url = URL_A;
    if (change === "digest") {
      requirements.extra.requestHash = "00".repeat(32);
    } else if (change === "resource") {
      url += "/wrong";
    } else if (change === "profile") {
      Object.assign(
        requirements.extra,
        extraOf(mcpToolCallBinding({ server: MCP_SERVER, name: "get_article", boundMetadata: [] })),
      );
    } else {
      requirements.extra.invoice = pyInvoice(binding().requestHash, { date: NOW - 301 });
    }
    await expect(client.createPaymentPayload(challenge(requirements, url))).rejects.toThrow(reason);
    expect(payer.payInvoice).not.toHaveBeenCalled();
  });

  const server = (options: Partial<ConstructorParameters<typeof LnbtcServer>[0]> = {}) =>
    new LnbtcServer({ receiver: pyReceiver(), requestBinding: binding, ...options });

  it.each([
    ["21 sat", "21000"],
    ["0.001 sats", "1"],
    [{ asset: "BTC", amount: "25000" }, "25000"],
  ])("test_explicit_millisatoshi_prices[%o]", async (price, expected) => {
    expect((await server().parsePrice(price, LNBTC_MAINNET)).amount).toBe(expected);
  });

  it.each([21, "21", "$1.00", "0 sats", "0.0001 sat", "-1 sat"])(
    "test_ambiguous_or_fractional_millisatoshi_prices_rejected[%o]",
    async price => {
      await expect(server().parsePrice(price, LNBTC_MAINNET)).rejects.toThrow();
    },
  );

  it("test_invoice_issuance_denied_before_calling_receiver", async () => {
    const receiver = pyReceiver();
    const scheme = server({ receiver, allowInvoice: () => false, clock: () => NOW });
    const base = requirement();
    base.extra = { assetTransferMethod: "bolt11", paymentFlow: "upfront" };
    const ctx = {
      requirements: [base],
      resourceInfo: { url: URL_A },
      paymentRequiredResponse: { x402Version: 2, resource: { url: URL_A }, accepts: [] },
    } as unknown as SchemePaymentRequiredContext;
    await expect(scheme.enrichPaymentRequiredResponse(ctx)).rejects.toThrow(
      "exact_lnbtc_invoice_issuance_denied",
    );
    expect(receiver.createInvoice).not.toHaveBeenCalled();
  });

  // One in-process stack: x402Facilitator -> x402ResourceServer -> x402Client.
  const stack = async (network: Network, current: () => RequestBinding) => {
    const receiver = pyReceiver();
    const facilitator = new x402Facilitator().register(network, pyFacilitator());
    const resourceServer = new x402ResourceServer(local(facilitator));
    resourceServer.register(
      network,
      new LnbtcServer({ receiver, requestBinding: () => current(), clock: () => NOW }),
    );
    await resourceServer.initialize();
    const client = sdkClient().register(
      network,
      new LnbtcClient({
        payer: pyPayer(receiver),
        requestBinding: () => current(),
        clock: () => NOW,
      }),
    );
    const config = {
      scheme: "exact",
      network,
      payTo: PAYEE,
      price: "21 sats",
      maxTimeoutSeconds: 300,
    };
    const issue = async () =>
      resourceServer.createPaymentRequiredResponse(
        await resourceServer.buildPaymentRequirements(config),
        { url: URL_A },
      );
    return { resourceServer, client, issue };
  };

  // Python's sync and async SDKs (this test and test_async_sdk_roundtrip) map
  // to the single asynchronous TypeScript SDK.
  it.each([
    [LNBTC_MAINNET, "http"],
    [LNBTC_MAINNET, "mcp"],
    [LNBTC_TESTNET, "http"],
    [LNBTC_TESTNET, "mcp"],
  ] as const)(
    "test_sdk_roundtrip_new_challenge_and_two_distinct_payments[%s-%s] (also test_async_sdk_roundtrip)",
    async (network, profile) => {
      const current =
        profile === "http"
          ? binding()
          : mcpToolCallBinding({
              server: MCP_SERVER,
              name: "get_article",
              arguments: { article: "A" },
              boundMetadata: [],
            });
      const { resourceServer, client, issue } = await stack(network, () => current);
      const first = await issue();
      const second = await issue();
      expect(first.accepts[0].extra.invoice).not.toBe(second.accepts[0].extra.invoice);
      const payloads = [];
      for (const required of [first, second])
        payloads.push(await client.createPaymentPayload(required));
      for (const payload of payloads) {
        const matched = resourceServer.findMatchingRequirements(second.accepts, payload);
        expect(matched).toBeDefined();
        expect((await resourceServer.settlePayment(payload, matched!)).success).toBe(true);
        expect((await resourceServer.settlePayment(payload, matched!)).errorReason).toBe(
          "duplicate_settlement",
        );
      }
    },
  );

  // Python re-checks the actual request in a before_settle hook. TypeScript
  // recomputes the requirements for each request (requestHash is not a
  // dynamic field), so a stale request no longer matches the payload, and
  // settling it anyway fails at the facilitator with the same reason.
  it("test_registered_server_hook_rejects_stale_actual_request", async () => {
    let current = binding();
    const { resourceServer, client, issue } = await stack(LNBTC_MAINNET, () => current);
    const payload = await client.createPaymentPayload(await issue());
    const retry = async () =>
      resourceServer.createPaymentRequiredResponse(
        await resourceServer.buildPaymentRequirements({
          scheme: "exact",
          network: LNBTC_MAINNET,
          payTo: PAYEE,
          price: "21 sats",
          maxTimeoutSeconds: 300,
        }),
        { url: current.resourceUrl! },
        undefined,
        undefined,
        {
          request: {
            adapter: {
              getHeader: (name: string) =>
                name === "payment-signature" ? encodePaymentSignatureHeader(payload) : undefined,
            },
          },
        },
      );

    current = http({ url: URL_A.slice(0, -1) + "B" });
    const stale = (await retry()).accepts;
    expect(resourceServer.findMatchingRequirements(stale, payload)).toBeUndefined();
    const forced: SettleResponse = await resourceServer.settlePayment(payload, {
      ...stale[0],
      extra: { ...stale[0].extra, invoice: payload.accepted.extra.invoice },
    });
    expect(forced.errorReason).toBe("invalid_exact_lnbtc_request_mismatch");

    current = binding();
    const matched = resourceServer.findMatchingRequirements((await retry()).accepts, payload);
    expect((await resourceServer.settlePayment(payload, matched!)).success).toBe(true);
  });

  // Flask middleware analog: x402HTTPResourceServer over a framework-style
  // adapter, binding the request with httpTransportBinding. The handler runs
  // only for a `payment-verified` result whose before-handler settlement
  // succeeded. The spoofed-Host request is d162e678's addition.
  it("test_flask_handler_runs_only_after_single_successful_settlement", async () => {
    const receiver = pyReceiver();
    const mechanism = pyFacilitator();
    const verify = vi.spyOn(mechanism, "verify").mockImplementation(() => {
      throw new Error("upfront must never verify");
    });
    const facilitator = new x402Facilitator().register(LNBTC_MAINNET, mechanism);
    const resourceServer = new x402ResourceServer(local(facilitator));
    resourceServer.register(
      LNBTC_MAINNET,
      new LnbtcServer({
        receiver,
        requestBinding: httpTransportBinding({ publicOrigin: ORIGIN }),
        clock: () => NOW,
      }),
    );
    await resourceServer.initialize();
    const route = {
      accepts: {
        scheme: "exact",
        network: LNBTC_MAINNET,
        payTo: PAYEE,
        price: "21 sats",
        maxTimeoutSeconds: 300,
      },
    };
    const httpServer = new x402HTTPResourceServer(resourceServer, {
      "GET /article/A": route,
      "GET /article/B": route,
    });
    await httpServer.initialize();

    const handled: string[] = [];
    // Builds getUrl() from the Host header like Express.
    const adapter = (path: string, given: Record<string, string>): HTTPAdapter => {
      const headers: Record<string, string> = { host: "api.example.com" };
      for (const [name, value] of Object.entries(given)) headers[name.toLowerCase()] = value;
      return {
        getHeader: name => headers[name.toLowerCase()],
        getMethod: () => "GET",
        getPath: () => path,
        getUrl: () => `https://${headers.host}${path}`,
        getAcceptHeader: () => "application/json",
        getUserAgent: () => "python-parity",
      };
    };
    const browserGet = async (path: string, headers: Record<string, string> = {}) => {
      const result = await httpServer.processHTTPRequest({
        adapter: adapter(path, headers),
        path,
        method: "GET",
      });
      const settled = (result as { beforeHandlerSettlement?: { result: SettleResponse } })
        .beforeHandlerSettlement?.result;
      if (result.type === "payment-verified" && settled?.success) handled.push(path);
      return result;
    };

    const unpaid = await browserGet("/article/A");
    expect(unpaid.type).toBe("payment-error");
    const response = (unpaid as { response: HTTPResponseInstructions }).response;
    expect(response.status).toBe(402);
    expect(handled).toEqual([]);

    const httpClient = new x402HTTPClient(
      sdkClient().register(
        LNBTC_MAINNET,
        new LnbtcClient({ payer: pyPayer(receiver), requestBinding: binding, clock: () => NOW }),
      ),
    );
    const required = httpClient.getPaymentRequiredResponse(
      name => response.headers[name],
      response.body,
    );
    const header = httpClient.encodePaymentSignatureHeader(
      await httpClient.createPaymentPayload(required),
    );

    // d162e678: a Host that would rewrite /article/B into /article/A is refused.
    await expect(
      browserGet("/article/B", { ...header, host: "api.example.com/article/A?q=" }),
    ).rejects.toThrow("invalid_exact_lnbtc_request_binding");
    expect(handled).toEqual([]);

    const paid = await browserGet("/article/A", header);
    expect(paid.type).toBe("payment-verified");
    expect(handled).toEqual(["/article/A"]);

    const replayed = await browserGet("/article/A", header);
    expect(replayed.type).toBe("payment-error");
    const replay = (replayed as { response: HTTPResponseInstructions }).response;
    expect(replay.status).toBe(402);
    expect(
      JSON.parse(Buffer.from(replay.headers["PAYMENT-RESPONSE"], "base64").toString()).errorReason,
    ).toBe("duplicate_settlement");
    expect(handled).toHaveLength(1);
    expect(verify).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// d162e678: authority header validation (later Python commit, not pinned)
// ---------------------------------------------------------------------------

describe("python parity: d162e678 authority headers (via httpTransportBinding)", () => {
  // Python's http(headers=...) keeps the URL fixed and adds the headers; the
  // TypeScript analog is a framework adapter whose URL is that same URL.
  const viaTransport = (
    headers: [string, string][],
    url = URL_A,
    publicOrigin = ORIGIN,
  ): Promise<RequestBinding> =>
    Promise.resolve().then(() =>
      httpTransportBinding({ publicOrigin })({
        request: {
          adapter: {
            getMethod: () => "GET",
            getUrl: () => url,
            getHeader: (name: string) => {
              const values = headerLookup(headers)(name);
              return values === undefined ? undefined : (values as string[]).join(", ");
            },
          },
        },
      } as unknown as HTTPTransportContext),
    );

  const authorities = [
    "api.example.com/article/A?q=",
    "api.example.com?query=",
    "api.example.com#fragment",
    "api.example.com\\other",
    "user@api.example.com",
    "api.example.com:bad",
    "api.example.com:65536",
    "api.example.com%zz",
    "foo[::1]bar",
    "api.example.com\r\n",
    "",
  ];
  it.each(
    ["Host", ":authority", "X-Forwarded-Host"].flatMap(name =>
      authorities.map(authority => [name, authority] as const),
    ),
  )("test_authority_headers_cannot_inject_a_request_target[%s-%j]", async (name, authority) => {
    await expect(viaTransport([[name, authority]])).rejects.toThrow(
      "invalid_exact_lnbtc_request_binding",
    );
  });

  // Python raises request_mismatch for a well-formed Host naming another
  // authority; TypeScript refuses with request_binding. Both are local server
  // reasons (not facilitator responses), and the request is refused either way.
  it("test_reconstructed_authority_must_match_a_validated_header (reason differs: request_binding vs request_mismatch)", async () => {
    await expect(viaTransport([["Host", "other.example.com"]])).rejects.toThrow(
      "invalid_exact_lnbtc_request_binding",
    );
    await expect(
      viaTransport([
        ["Host", "api.example.com"],
        ["X-Forwarded-Host", "bad/path"],
      ]),
    ).rejects.toThrow("invalid_exact_lnbtc_request_binding");
  });

  it.each([
    [[["Host", "API.EXAMPLE.COM"]]],
    [[["Host", "api.example.com:443"]]],
    [[[":authority", "api.example.com"]]],
    [
      [
        ["Host", "internal:8080"],
        ["X-Forwarded-Host", "api.example.com, proxy:8080"],
      ],
    ],
  ] as [string, string][][][])(
    "test_valid_authority_headers_preserve_the_published_hash[%j]",
    async headers => {
      expect((await viaTransport(headers)).requestHash).toBe(http().requestHash);
    },
  );

  it.each(["https://api.example.com/path?", "https\r\n", "https, "])(
    "test_forwarded_scheme_cannot_inject_a_request_target[%j]",
    async proto => {
      await expect(
        viaTransport([
          ["Host", "api.example.com"],
          ["X-Forwarded-Proto", proto],
        ]),
      ).rejects.toThrow("invalid_exact_lnbtc_request_binding");
    },
  );

  it("test_valid_forwarded_scheme_hops_preserve_the_published_hash", async () => {
    const headers: [string, string][] = [
      ["Host", "api.example.com"],
      ["X-Forwarded-Proto", "https, http"],
    ];
    expect((await viaTransport(headers)).requestHash).toBe(http().requestHash);
  });

  it("test_bracketed_ipv6_authority_matches_without_rewriting_the_target", async () => {
    const url = "https://[::1]:8443/article/A?x=%2F";
    const bound = await viaTransport([["Host", "[::1]:8443"]], url, "https://[::1]:8443");
    expect(bound).toEqual(http({ url }));
  });

  // Python accepts a request that carries no authority header at all (it only
  // checks the headers that are present); TypeScript refuses it, because the
  // adapter URL's authority must come from a validated header.
  it("DIVERGENCE no authority header: TypeScript refuses, Python d162e678 binds", async () => {
    await expect(viaTransport([])).rejects.toThrow("invalid_exact_lnbtc_request_binding");
  });
});

// ---------------------------------------------------------------------------
// Divergences found by reading the Python sources beyond its test suite
// ---------------------------------------------------------------------------

describe("python parity: behavior beyond the Python suite", () => {
  const settleWith = async (
    mutateAccepted: (r: PaymentRequirements) => void,
    mutateRequired: (r: PaymentRequirements) => void = () => {},
  ) => {
    const [payload, requirements] = proof();
    mutateAccepted(payload.accepted);
    mutateRequired(requirements);
    return (await pyFacilitator().settle(payload, requirements)).errorReason;
  };

  // Python checks asset == "BTC" before comparing amounts. The spec's step 1
  // lists amount before asset; TypeScript compares in that order.
  it("DIVERGENCE accepted asset 'btc' and amount '1': TypeScript reports the amount mismatch first", async () => {
    expect(await settleWith(r => ((r.asset = "btc"), (r.amount = "1")))).toBe(
      "invalid_exact_lnbtc_amount_mismatch",
    );
  });

  // Python validates each whole side (method, flow, binding, invoice presence)
  // before matching the bindings, so it reports a missing invoice ahead of a
  // step-3 failure. The spec puts step 3 (method, flow, binding match) before
  // step 4 (invoices present); TypeScript follows it.
  it("DIVERGENCE empty requirements invoice with a missing accepted paymentFlow: step 3 first", async () => {
    expect(
      await settleWith(
        r => delete r.extra.paymentFlow,
        r => (r.extra.invoice = ""),
      ),
    ).toBe("invalid_exact_lnbtc_payment_flow");
  });

  it("DIVERGENCE empty accepted invoice with a different accepted requestHash: step 3 first", async () => {
    const other = http({ url: "https://api.example.com/article/B" }).requestHash;
    expect(await settleWith(r => ((r.extra.invoice = ""), (r.extra.requestHash = other)))).toBe(
      "invalid_exact_lnbtc_request_mismatch",
    );
  });

  // Python's client and server treat an invoice as unexpired while
  // now <= created + expiry; TypeScript's while now < created + expiry. At
  // exactly created + expiry Python pays and TypeScript refuses. The spec says
  // only "has not expired"; the facilitator's +skew window covers both.
  it("DIVERGENCE client at now == created + expiry: TypeScript refuses, Python pays", async () => {
    const payer = pyPayer();
    const client = new LnbtcClient({
      payer,
      requestBinding: () => http(),
      clock: () => NOW + 300,
    });
    const requirements: PaymentRequirements = {
      ...(proof()[1] as PaymentRequirements),
      amount: "21000",
      extra: { ...proof()[1].extra, invoice: pyInvoice(http().requestHash) },
    };
    await expect(client.createPaymentPayload(2, requirements)).rejects.toThrow(
      "invalid_exact_lnbtc_invoice_expired",
    );
    expect(payer.payInvoice).not.toHaveBeenCalled();
  });

  // Python's validate_uri refuses port 0 (it requires 0 < port <= 65535);
  // RFC 3986 and the WHATWG URL parser accept it, and so does TypeScript.
  it("DIVERGENCE port 0: TypeScript binds https://api.example.com:0/a, Python refuses", () => {
    expect(http({ url: "https://api.example.com:0/a" }).requestHash).toMatch(/^[0-9a-f]{64}$/);
    expect(() => http({ url: "https://api.example.com:65536/a" })).toThrow(
      "invalid_exact_lnbtc_request_binding",
    );
  });
});
