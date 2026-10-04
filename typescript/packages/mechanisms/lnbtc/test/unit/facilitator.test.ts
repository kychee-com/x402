import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";
import { describe, expect, it } from "vitest";
import { LNBTC_MAINNET, LNBTC_TESTNET } from "../../src/constants";
import { ExactLnbtcScheme } from "../../src/exact/facilitator";
import { InMemoryReplayStore } from "../../src/replayStore";
import type { ReplayStore } from "../../src/types";
import {
  OTHER_KEY,
  SPEC_PREIMAGE,
  SPEC_TIME,
  httpArticle,
  makeInvoice,
  mcpArticle,
  payloadFor,
  requirementsFor,
} from "./helpers";

const facilitator = (now = SPEC_TIME, store: ReplayStore = new InMemoryReplayStore()) =>
  new ExactLnbtcScheme({ replayStore: store, clock: () => now });

const settle = (
  payload: PaymentPayload = payloadFor(),
  requirements: PaymentRequirements = requirementsFor(),
  scheme = facilitator(),
) => scheme.settle(payload, requirements);

const PREIMAGE_B = "ff".repeat(32);

describe("facilitator metadata", () => {
  it("advertises bolt11/upfront, has no signers, and refuses /verify", async () => {
    const f = facilitator();
    expect(f.scheme).toBe("exact");
    expect(f.caipFamily).toBe("lnbtc:*");
    expect(f.getExtra(LNBTC_MAINNET)).toEqual({
      assetTransferMethod: "bolt11",
      paymentFlow: "upfront",
    });
    expect(f.getExtra("lnbtc:unknown")).toBeUndefined();
    expect(f.getSigners(LNBTC_MAINNET)).toEqual([]);
    expect(await f.verify(payloadFor(), requirementsFor())).toEqual({
      isValid: false,
      invalidReason: "invalid_exact_lnbtc_payment_flow",
    });
  });

  it("rejects a negative or fractional clock skew", () => {
    const replayStore = new InMemoryReplayStore();
    expect(() => new ExactLnbtcScheme({ replayStore, clockSkewSeconds: -1 })).toThrow(RangeError);
    expect(() => new ExactLnbtcScheme({ replayStore, clockSkewSeconds: 1.5 })).toThrow(RangeError);
  });
});

describe("HTTP settlement vectors (specification)", () => {
  it("settles the unchanged example and reports the payment hash", async () => {
    expect(await settle()).toEqual({
      success: true,
      transaction: "a923c2c0e4fe77061ff1cb882171f6fdf926719bb7f5ffe2e05458438c52825e",
      network: LNBTC_MAINNET,
    });
  });

  it("settles with the accepted invoice when the requirements carry a fresh one", async () => {
    const fresh = makeInvoice({ preimage: PREIMAGE_B }).invoice;
    expect((await settle(payloadFor(), requirementsFor(httpArticle(), fresh))).success).toBe(true);
  });

  it("accepts an unused proof against a second challenge for the same request", async () => {
    const second = requirementsFor(httpArticle(), makeInvoice({ preimage: PREIMAGE_B }).invoice);
    expect((await settle(payloadFor(), second)).success).toBe(true);
  });

  it("settles a proof presented concurrently exactly once", async () => {
    const f = facilitator();
    const second = requirementsFor(httpArticle(), makeInvoice({ preimage: PREIMAGE_B }).invoice);
    const results = await Promise.all([
      settle(payloadFor(), requirementsFor(), f),
      settle(payloadFor(), second, f),
    ]);
    expect(results.map(r => r.success).sort()).toEqual([false, true]);
    expect(results.find(r => !r.success)?.errorReason).toBe("duplicate_settlement");
  });

  it("settles two paid invoices for the same request independently", async () => {
    const f = facilitator();
    const b = makeInvoice({ preimage: PREIMAGE_B }).invoice;
    expect((await settle(payloadFor(), requirementsFor(), f)).success).toBe(true);
    const payloadB = payloadFor(requirementsFor(httpArticle(), b), PREIMAGE_B);
    expect((await settle(payloadB, requirementsFor(), f)).success).toBe(true);
  });

  it("rejects article A's proof for an actual request for article B", async () => {
    expect((await settle(payloadFor(), requirementsFor(httpArticle("B")))).errorReason).toBe(
      "invalid_exact_lnbtc_request_mismatch",
    );
  });

  it("rejects an echoed digest for B against an invoice committing to A", async () => {
    const accepted = requirementsFor(httpArticle("B"));
    expect(
      (await settle(payloadFor(accepted), requirementsFor(httpArticle("B")))).errorReason,
    ).toBe("invalid_exact_lnbtc_invoice_request_mismatch");
  });

  it.each([
    ["POST", httpArticle("A", { method: "POST" })],
    ["body 0x78", httpArticle("A", { body: Uint8Array.of(0x78) })],
  ])("rejects a changed request (%s) with an echoed digest", async (_name, binding) => {
    const r = requirementsFor(binding);
    expect((await settle(payloadFor(r), r)).errorReason).toBe(
      "invalid_exact_lnbtc_invoice_request_mismatch",
    );
  });

  it.each(["requestHash", "requestBindingProfile", "requestBindingParams"])(
    "rejects a missing %s on either side",
    async field => {
      const stripped = requirementsFor();
      delete stripped.extra[field];
      expect((await settle(payloadFor(stripped), requirementsFor())).errorReason).toBe(
        "invalid_exact_lnbtc_request_binding",
      );
      expect((await settle(payloadFor(), stripped)).errorReason).toBe(
        "invalid_exact_lnbtc_request_binding",
      );
    },
  );

  it.each([
    ["unknown profile", { requestBindingProfile: "http:9" }],
    ["missing parameters", { requestBindingParams: {} }],
    ["unknown parameter", { requestBindingParams: { headers: [], other: true } }],
  ])("rejects an %s", async (_name, patch) => {
    const r = requirementsFor();
    Object.assign(r.extra, patch);
    expect((await settle(payloadFor(r), r)).errorReason).toBe(
      "invalid_exact_lnbtc_request_binding",
    );
  });

  it("rejects a change to only the accepted header list", async () => {
    const accepted = requirementsFor();
    accepted.extra.requestBindingParams = { headers: ["accept"] };
    expect((await settle(payloadFor(accepted), requirementsFor())).errorReason).toBe(
      "invalid_exact_lnbtc_request_mismatch",
    );
  });

  it("rejects an invoice with an inline description", async () => {
    const inline = makeInvoice({ description: "article A", descriptionHash: null }).invoice;
    expect((await settle(payloadFor(requirementsFor(httpArticle(), inline)))).errorReason).toBe(
      "invalid_exact_lnbtc_invoice_description",
    );
  });
});

describe("MCP settlement vectors (specification)", () => {
  const mcpInvoice = makeInvoice({ descriptionHash: mcpArticle().requestHash }).invoice;
  const mcpRequirements = (binding = mcpArticle()) => requirementsFor(binding, mcpInvoice);

  it("settles a retried tool call", async () => {
    expect((await settle(payloadFor(mcpRequirements()), mcpRequirements())).success).toBe(true);
  });

  it("rejects a changed tool call, with or without an echoed digest", async () => {
    expect(
      (await settle(payloadFor(mcpRequirements()), mcpRequirements(mcpArticle("B")))).errorReason,
    ).toBe("invalid_exact_lnbtc_request_mismatch");
    const changed = mcpRequirements(mcpArticle("B"));
    expect((await settle(payloadFor(changed), changed)).errorReason).toBe(
      "invalid_exact_lnbtc_invoice_request_mismatch",
    );
  });

  it("rejects the HTTP invoice with MCP binding fields", async () => {
    const r = requirementsFor(mcpArticle());
    expect((await settle(payloadFor(r), r)).errorReason).toBe(
      "invalid_exact_lnbtc_invoice_request_mismatch",
    );
  });

  it("rejects a profile change to http:1 on the accepted side only", async () => {
    const accepted = mcpRequirements(httpArticle());
    expect((await settle(payloadFor(accepted), mcpRequirements())).errorReason).toBe(
      "invalid_exact_lnbtc_request_mismatch",
    );
  });
});

describe("core field, invoice, and preimage checks", () => {
  const mutateAccepted = async (mutate: (r: PaymentRequirements) => void) => {
    const accepted = requirementsFor();
    mutate(accepted);
    return (await settle(payloadFor(accepted))).errorReason;
  };
  const mutateBoth = async (mutate: (r: PaymentRequirements) => void) => {
    const r = requirementsFor();
    mutate(r);
    return (await settle(payloadFor(r), r)).errorReason;
  };

  it.each([
    [(r: PaymentRequirements) => (r.scheme = "upto"), "unsupported_scheme"],
    [(r: PaymentRequirements) => (r.network = LNBTC_TESTNET), "network_mismatch"],
    [(r: PaymentRequirements) => (r.amount = "25001"), "invalid_exact_lnbtc_amount_mismatch"],
    [(r: PaymentRequirements) => (r.asset = "SAT"), "invalid_exact_lnbtc_asset"],
    [
      (r: PaymentRequirements) => (r.payTo = "02" + "ab".repeat(32)),
      "invalid_exact_lnbtc_pay_to_mismatch",
    ],
    [
      (r: PaymentRequirements) => (r.maxTimeoutSeconds = 301),
      "invalid_exact_lnbtc_max_timeout_mismatch",
    ],
    [
      (r: PaymentRequirements) => (r.extra.assetTransferMethod = "invoice"),
      "invalid_exact_lnbtc_asset_transfer_method",
    ],
    [(r: PaymentRequirements) => delete r.extra.paymentFlow, "invalid_exact_lnbtc_payment_flow"],
    [(r: PaymentRequirements) => (r.extra.invoice = ""), "invalid_exact_lnbtc_invoice_missing"],
  ])("rejects a mismatched accepted field (%#)", async (mutate, reason) => {
    expect(await mutateAccepted(mutate)).toBe(reason);
  });

  it.each([
    [(r: PaymentRequirements) => (r.network = "lnbtc:0000"), "unsupported_network"],
    [(r: PaymentRequirements) => (r.amount = "0"), "invalid_exact_lnbtc_amount"],
    [(r: PaymentRequirements) => (r.amount = "1.5"), "invalid_exact_lnbtc_amount"],
    [(r: PaymentRequirements) => (r.maxTimeoutSeconds = 0), "invalid_exact_lnbtc_max_timeout"],
    [
      (r: PaymentRequirements) => (r.payTo = r.payTo.toUpperCase()),
      "invalid_exact_lnbtc_pay_to_malformed",
    ],
    [
      (r: PaymentRequirements) => (r.payTo = "04" + "ab".repeat(32)),
      "invalid_exact_lnbtc_pay_to_malformed",
    ],
    [
      (r: PaymentRequirements) => (r.payTo = "02" + "ff".repeat(32)),
      "invalid_exact_lnbtc_pay_to_malformed",
    ],
    [
      (r: PaymentRequirements) => (r.extra.paymentFlow = "authorization"),
      "invalid_exact_lnbtc_payment_flow",
    ],
    [
      (r: PaymentRequirements) => (r.extra.invoice = "lnbc1garbage"),
      "invalid_exact_lnbtc_invoice_decode_failed",
    ],
    [
      (r: PaymentRequirements) => (r.payTo = "03" + "cd".repeat(32)),
      "invalid_exact_lnbtc_pay_to_malformed",
    ],
  ])("rejects invalid terms on both sides (%#)", async (mutate, reason) => {
    expect(await mutateBoth(mutate)).toBe(reason);
  });

  it("resolves an omitted transfer method to bolt11 on both sides", async () => {
    expect(await mutateBoth(r => delete r.extra.assetTransferMethod)).toBeUndefined();
  });

  it("rejects a mismatched server-declared extra field but allows additive client fields", async () => {
    const r = requirementsFor();
    r.extra.campaign = { id: 1 };
    const accepted = requirementsFor();
    expect((await settle(payloadFor(accepted), r)).errorReason).toBe(
      "invalid_exact_lnbtc_extra_mismatch",
    );
    accepted.extra.campaign = { id: 2 };
    expect((await settle(payloadFor(accepted), r)).errorReason).toBe(
      "invalid_exact_lnbtc_extra_mismatch",
    );
    const additive = structuredClone(r);
    additive.extra.clientNote = "x";
    expect((await settle(payloadFor(additive), r)).success).toBe(true);
  });

  it("requires an invoice in the server requirements too", async () => {
    const r = requirementsFor();
    delete r.extra.invoice;
    expect((await settle(payloadFor(), r)).errorReason).toBe("invalid_exact_lnbtc_invoice_missing");
  });

  it.each([
    [{ key: OTHER_KEY }, "invalid_exact_lnbtc_invoice_payee_mismatch"],
    [{ currency: "tb" }, "invalid_exact_lnbtc_invoice_currency_mismatch"],
    [{ amountMsat: 26_000n }, "invalid_exact_lnbtc_invoice_amount_mismatch"],
    [{ expiry: 600 }, "invalid_exact_lnbtc_invoice_expiry_mismatch"],
    [{ timestamp: SPEC_TIME + 61 }, "invalid_exact_lnbtc_invoice_created_in_future"],
    [{ descriptionHash: null }, "invalid_exact_lnbtc_invoice_description"],
  ])("rejects an accepted invoice with %o", async (spec, reason) => {
    const accepted = requirementsFor(httpArticle(), makeInvoice(spec).invoice);
    expect((await settle(payloadFor(accepted))).errorReason).toBe(reason);
  });

  it("accepts a creation time exactly at the skew boundary", async () => {
    const accepted = requirementsFor(
      httpArticle(),
      makeInvoice({ timestamp: SPEC_TIME + 60 }).invoice,
    );
    expect((await settle(payloadFor(accepted))).success).toBe(true);
  });

  it.each([
    [undefined, "invalid_exact_lnbtc_preimage_missing"],
    ["AB".repeat(32), "invalid_exact_lnbtc_preimage_malformed"],
    ["zz", "invalid_exact_lnbtc_preimage_malformed"],
    ["ab".repeat(31), "invalid_exact_lnbtc_preimage_length"],
    ["ab".repeat(33), "invalid_exact_lnbtc_preimage_length"],
    [PREIMAGE_B, "invalid_exact_lnbtc_preimage_hash_mismatch"],
  ])("rejects preimage %s", async (preimage, reason) => {
    const payload = payloadFor();
    payload.payload = preimage === undefined ? {} : { preimage };
    expect((await settle(payload)).errorReason).toBe(reason);
  });
});

describe("paid-but-expired policy and replay keys", () => {
  const end = SPEC_TIME + 300;

  it("accepts settlement through invoice end plus skew, inclusive", async () => {
    expect((await settle(payloadFor(), requirementsFor(), facilitator(end))).success).toBe(true);
    expect((await settle(payloadFor(), requirementsFor(), facilitator(end + 60))).success).toBe(
      true,
    );
  });

  it("rejects settlement after the boundary", async () => {
    expect((await settle(payloadFor(), requirementsFor(), facilitator(end + 61))).errorReason).toBe(
      "invalid_exact_lnbtc_invoice_expired",
    );
  });

  it("keys consumption by network and payment hash, retained an hour past the window", async () => {
    const calls: [string, number][] = [];
    const store: ReplayStore = { consume: async (key, until) => (calls.push([key, until]), true) };
    await settle(payloadFor(), requirementsFor(), facilitator(SPEC_TIME, store));
    expect(calls).toEqual([
      [
        `${LNBTC_MAINNET}:a923c2c0e4fe77061ff1cb882171f6fdf926719bb7f5ffe2e05458438c52825e`,
        end + 60 + 3600,
      ],
    ]);
  });

  it("does not consume a proof that fails validation", async () => {
    const f = facilitator();
    expect((await settle(payloadFor(), requirementsFor(httpArticle("B")), f)).success).toBe(false);
    expect((await settle(payloadFor(), requirementsFor(), f)).success).toBe(true);
  });

  it("denies settlement when the replay store fails", async () => {
    const store: ReplayStore = { consume: async () => Promise.reject(new Error("db down")) };
    await expect(
      settle(payloadFor(), requirementsFor(), facilitator(SPEC_TIME, store)),
    ).rejects.toThrow("db down");
  });

  it("preserves the spec preimage relationship", () => {
    expect(makeInvoice({ preimage: SPEC_PREIMAGE }).paymentHash).toBe(
      "a923c2c0e4fe77061ff1cb882171f6fdf926719bb7f5ffe2e05458438c52825e",
    );
  });
});
