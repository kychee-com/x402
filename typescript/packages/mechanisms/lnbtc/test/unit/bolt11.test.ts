import { bech32 } from "@scure/base";
import { describe, expect, it } from "vitest";
import { decodeInvoice } from "../../src/bolt11";
import {
  HTTP_A_HASH,
  OTHER_KEY,
  RECEIVER_PUBKEY,
  SPEC_INVOICE,
  SPEC_TIME,
  makeInvoice,
} from "./helpers";

describe("decodeInvoice", () => {
  it("decodes the specification vector", () => {
    expect(decodeInvoice(SPEC_INVOICE)).toEqual({
      currency: "bc",
      amountMsat: 25_000n,
      timestamp: SPEC_TIME,
      expirySeconds: 300,
      paymentHash: "a923c2c0e4fe77061ff1cb882171f6fdf926719bb7f5ffe2e05458438c52825e",
      descriptionHashes: [HTTP_A_HASH],
      inlineDescriptionCount: 0,
      payee: RECEIVER_PUBKEY,
      hasPayeeField: false,
    });
  });

  it("reproduces the specification vector from its inputs", () => {
    expect(makeInvoice().invoice).toBe(SPEC_INVOICE);
  });

  it("accepts an uppercase invoice", () => {
    expect(decodeInvoice(SPEC_INVOICE.toUpperCase()).paymentHash).toBe(
      decodeInvoice(SPEC_INVOICE).paymentHash,
    );
  });

  it.each([
    [1n, "1 msat (pico)"],
    [1_000n, "1 sat"],
    [21_000n, "21 sats"],
    [100_000_000_000n, "1 BTC"],
    [150_000_000n, "milli"],
    [100_000n, "micro"],
  ])("decodes amount %s (%s)", amount => {
    expect(decodeInvoice(makeInvoice({ amountMsat: amount }).invoice).amountMsat).toBe(amount);
  });

  it("verifies against an explicit payee field", () => {
    const decoded = decodeInvoice(makeInvoice({ payeeField: true }).invoice);
    expect(decoded.payee).toBe(RECEIVER_PUBKEY);
    expect(decoded.hasPayeeField).toBe(true);
  });

  it("reports description fields and default expiry", () => {
    const inline = decodeInvoice(makeInvoice({ description: "hi", descriptionHash: null }).invoice);
    expect(inline.descriptionHashes).toEqual([]);
    expect(inline.inlineDescriptionCount).toBe(1);
    expect(decodeInvoice(makeInvoice({ expiry: null }).invoice).expirySeconds).toBe(3600);
    expect(decodeInvoice(makeInvoice({ unknownField: true }).invoice).paymentHash).toMatch(
      /^[0-9a-f]{64}$/,
    );
  });

  it("recovers a different signer", () => {
    expect(decodeInvoice(makeInvoice({ key: OTHER_KEY }).invoice).payee).not.toBe(RECEIVER_PUBKEY);
  });

  // Flips one signed data word and re-encodes with a valid checksum.
  const tamper = (invoice: string) => {
    const { prefix, words } = bech32.decode(invoice as `${string}1${string}`, false);
    const flipped = [...words];
    flipped[3] ^= 1;
    return bech32.encode(prefix, flipped, false);
  };

  it.each([
    ["empty", ""],
    ["lightning: prefix", `lightning:${SPEC_INVOICE}`],
    ["mixed case", SPEC_INVOICE.slice(0, 10).toUpperCase() + SPEC_INVOICE.slice(10)],
    ["bad checksum", SPEC_INVOICE.slice(0, -1) + "q"],
    ["no amount", makeInvoice({ amountMsat: null }).invoice],
    ["leading zero", makeInvoice({ hrp: "lnbc0250n" }).invoice],
    ["zero amount", makeInvoice({ hrp: "lnbc0n" }).invoice],
    ["sub-msat", makeInvoice({ hrp: "lnbc1p" }).invoice],
    ["unknown multiplier", makeInvoice({ hrp: "lnbc250x" }).invoice],
    ["two payment hashes", makeInvoice({ extraPaymentHash: true }).invoice],
    ["no payment secret", makeInvoice({ omitPaymentSecret: true }).invoice],
    ["not a lightning prefix", makeInvoice({ hrp: "lxbc250n" }).invoice],
    ["no currency", makeInvoice({ hrp: "ln250n" }).invoice],
  ])("rejects %s", (_name, invoice) => {
    expect(() => decodeInvoice(invoice)).toThrow();
  });

  it("recovers a different payee from tampered data, and rejects it against an n field", () => {
    expect(decodeInvoice(tamper(SPEC_INVOICE)).payee).not.toBe(RECEIVER_PUBKEY);
    const withPayee = makeInvoice({ payeeField: true }).invoice;
    expect(() => decodeInvoice(tamper(withPayee))).toThrow();
  });
});
