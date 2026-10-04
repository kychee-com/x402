import { encodePaymentSignatureHeader, type HTTPTransportContext } from "@x402/core/http";
import type { PaymentRequirements, SchemePaymentRequiredContext } from "@x402/core/types";
import { describe, expect, it, vi } from "vitest";
import { LNBTC_MAINNET } from "../../src/constants";
import {
  ExactLnbtcScheme,
  httpTransportBinding,
  mcpTransportBinding,
} from "../../src/exact/server";
import type { CreateInvoiceParams, LightningReceiver } from "../../src/types";
import {
  HTTP_A_HASH,
  MCP_A_HASH,
  OTHER_KEY,
  RECEIVER_PUBKEY,
  SPEC_INVOICE,
  SPEC_TIME,
  httpArticle,
  makeInvoice,
  payloadFor,
  requirementsFor,
} from "./helpers";

const receiverReturning = (invoice = SPEC_INVOICE) => {
  const receiver: LightningReceiver = {
    createInvoice: vi.fn(async (_params: CreateInvoiceParams) => invoice),
  };
  return receiver;
};

const server = (receiver = receiverReturning(), allowInvoice?: () => boolean) =>
  new ExactLnbtcScheme({
    receiver,
    requestBinding: () => httpArticle(),
    allowInvoice,
    clock: () => SPEC_TIME,
  });

const base = (): PaymentRequirements => {
  const r = requirementsFor();
  r.extra = { assetTransferMethod: "bolt11", paymentFlow: "upfront" };
  return r;
};

const ctx = (overrides: Partial<SchemePaymentRequiredContext> = {}): SchemePaymentRequiredContext =>
  ({
    requirements: [base()],
    resourceInfo: { url: "https://api.example.com/article/A" },
    paymentRequiredResponse: { x402Version: 2, resource: { url: "" }, accepts: [] },
    ...overrides,
  }) as SchemePaymentRequiredContext;

describe("parsePrice", () => {
  const s = server();
  it.each([
    [{ asset: "BTC", amount: "21000" }, "21000"],
    ["21 sats", "21000"],
    ["1 sat", "1000"],
    ["21.5 sats", "21500"],
    ["0.001 sat", "1"],
    ["1.2340 sats", "1234"],
  ])("converts %o to %s msat", async (price, msat) => {
    expect(await s.parsePrice(price, LNBTC_MAINNET)).toEqual({ asset: "BTC", amount: msat });
  });

  it.each(["21", 21, "$1", "1 USD", "0.0001 BTC", "0.0001 sat", "-1 sats", "0 sats"])(
    "rejects %o without a registered parser",
    async price => {
      await expect(s.parsePrice(price, LNBTC_MAINNET)).rejects.toThrow();
    },
  );

  it("rejects wrong assets, bad amounts, and unsupported networks", async () => {
    await expect(s.parsePrice({ asset: "USDC", amount: "1" }, LNBTC_MAINNET)).rejects.toThrow(
      "invalid_exact_lnbtc_asset",
    );
    await expect(s.parsePrice({ asset: "BTC", amount: "1.5" }, LNBTC_MAINNET)).rejects.toThrow(
      "invalid_exact_lnbtc_amount",
    );
    await expect(s.parsePrice("1 sat", "eip155:8453")).rejects.toThrow("unsupported_network");
  });

  it("uses registered conversions for other forms", async () => {
    const converted = server().registerMoneyParser(async price =>
      price === "$1" ? { asset: "BTC", amount: "1500000" } : null,
    );
    expect(await converted.parsePrice("$1", LNBTC_MAINNET)).toEqual({
      asset: "BTC",
      amount: "1500000",
    });
    await expect(converted.parsePrice("$2", LNBTC_MAINNET)).rejects.toThrow();
  });
});

describe("requirements and challenges", () => {
  it("declares the bolt11/upfront flow and the dynamic invoice field", async () => {
    const s = server();
    expect(s.defaultAssetTransferMethod).toBe("bolt11");
    expect(s.paymentFlows).toEqual({ bolt11: { supported: ["upfront"], default: "upfront" } });
    expect(s.dynamicExtraFields).toEqual(["invoice"]);
    const enhanced = await s.enhancePaymentRequirements(
      { ...base(), extra: {} },
      { x402Version: 2, scheme: "exact", network: LNBTC_MAINNET },
      [],
    );
    expect(enhanced.extra).toEqual({ assetTransferMethod: "bolt11", paymentFlow: "upfront" });
  });

  it("binds the challenge to the request and issues a fresh invoice", async () => {
    const receiver = receiverReturning();
    const [r] = await server(receiver).enrichPaymentRequiredResponse(ctx());
    expect(r).toEqual(requirementsFor());
    expect(receiver.createInvoice).toHaveBeenCalledWith({
      amountMsat: 25_000n,
      descriptionHash: HTTP_A_HASH,
      expirySeconds: 300,
      network: LNBTC_MAINNET,
    });
  });

  it("reuses the accepted invoice on a paid retry instead of issuing one", async () => {
    const receiver = receiverReturning(makeInvoice({ preimage: "ff".repeat(32) }).invoice);
    const header = encodePaymentSignatureHeader(payloadFor());
    const transportContext = {
      request: { paymentHeader: header },
    } as unknown as HTTPTransportContext;
    const [r] = await server(receiver).enrichPaymentRequiredResponse(ctx({ transportContext }));
    expect(r.extra.invoice).toBe(SPEC_INVOICE);
    expect(r.extra.requestHash).toBe(HTTP_A_HASH);
    expect(receiver.createInvoice).not.toHaveBeenCalled();

    const meta = { meta: { "x402/payment": payloadFor() } };
    await server(receiver).enrichPaymentRequiredResponse(ctx({ transportContext: meta }));
    await server(receiver).enrichPaymentRequiredResponse(ctx({ paymentPayload: payloadFor() }));
    expect(receiver.createInvoice).not.toHaveBeenCalled();
  });

  it("issues a fresh invoice when reporting an error or given a malformed header", async () => {
    const receiver = receiverReturning();
    await server(receiver).enrichPaymentRequiredResponse(
      ctx({ paymentPayload: payloadFor(), error: "No matching payment requirements" }),
    );
    const transportContext = { request: { paymentHeader: "!!" } };
    await server(receiver).enrichPaymentRequiredResponse(ctx({ transportContext }));
    expect(receiver.createInvoice).toHaveBeenCalledTimes(2);
  });

  it("passes through requirements of other schemes and networks", async () => {
    const other = { ...base(), scheme: "upto" };
    const evm = { ...base(), network: "eip155:8453" };
    const out = await server().enrichPaymentRequiredResponse(ctx({ requirements: [other, evm] }));
    expect(out).toEqual([other, evm]);
  });

  it("denies issuance when the limiter refuses", async () => {
    const receiver = receiverReturning();
    await expect(
      server(receiver, () => false).enrichPaymentRequiredResponse(ctx()),
    ).rejects.toThrow("exact_lnbtc_invoice_issuance_denied");
    expect(receiver.createInvoice).not.toHaveBeenCalled();
  });

  it.each([
    [{ key: OTHER_KEY }, "invalid_exact_lnbtc_invoice_payee_mismatch"],
    [{ descriptionHash: MCP_A_HASH }, "invalid_exact_lnbtc_invoice_request_mismatch"],
    [{ amountMsat: 1_000n }, "invalid_exact_lnbtc_invoice_amount_mismatch"],
  ])("refuses a receiver invoice with %o", async (spec, reason) => {
    const receiver = receiverReturning(makeInvoice(spec).invoice);
    await expect(server(receiver).enrichPaymentRequiredResponse(ctx())).rejects.toThrow(reason);
  });

  it("validates the payTo key before issuing", async () => {
    const r = { ...base(), payTo: RECEIVER_PUBKEY.toUpperCase() };
    await expect(
      server().enrichPaymentRequiredResponse(ctx({ requirements: [r] })),
    ).rejects.toThrow("invalid_exact_lnbtc_pay_to_malformed");
  });
});

describe("transport bindings", () => {
  const adapter = (url: string, headers: Record<string, string> = {}, method = "GET") => ({
    getMethod: () => method,
    getUrl: () => url,
    getHeader: (name: string) => headers[name],
  });
  const http = (
    url: string,
    headers?: Record<string, string>,
    body?: Uint8Array,
    bound?: string[],
  ) =>
    httpTransportBinding({
      publicOrigin: "https://api.example.com/",
      boundHeaders: bound,
      rawBody: () => body,
    })({ request: { adapter: adapter(url, headers) } });

  it("uses the configured origin, never the Host header", async () => {
    expect((await http("http://evil.example:8080/article/A")).requestHash).toBe(HTTP_A_HASH);
    expect((await http("https://api.example.com/article/A#frag")).requestHash).toBe(HTTP_A_HASH);
  });

  it("preserves the raw target and binds configured headers and the body", async () => {
    const a = await http("https://x/article/A?b=2&a=1");
    const b = await http("https://x/article/A?a=1&b=2");
    expect(a.resourceUrl).toBe("https://api.example.com/article/A?b=2&a=1");
    expect(a.requestHash).not.toBe(b.requestHash);
    const withHeader = await http("https://x/article/A", { accept: "text/plain" }, undefined, [
      "accept",
    ]);
    expect(withHeader.requestBindingParams).toEqual({ headers: ["accept"] });
    expect((await http("https://x/article/A", {}, Uint8Array.of(1))).requestHash).not.toBe(
      HTTP_A_HASH,
    );
    expect((await http("https://api.example.com")).resourceUrl).toBe("https://api.example.com/");
  });

  it("rejects a missing transport context", () => {
    expect(() => httpTransportBinding({ publicOrigin: "https://a.example" })(undefined)).toThrow(
      "invalid_exact_lnbtc_request_binding",
    );
  });

  it("binds MCP tool calls from the wrapper context", async () => {
    const bind = mcpTransportBinding({ server: "https://api.example.com/mcp" });
    expect((await bind({ toolName: "get_article", arguments: { article: "A" } })).requestHash).toBe(
      MCP_A_HASH,
    );
    expect(() => bind({ arguments: {} })).toThrow("invalid_exact_lnbtc_request_binding");
  });
});
