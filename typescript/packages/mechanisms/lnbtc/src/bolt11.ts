import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { bech32, utils as scure } from "@scure/base";

/**
 * Strictly decoded BOLT11 invoice fields used by the lnbtc scheme.
 */
export interface DecodedInvoice {
  /** BOLT11 currency prefix (e.g. `bc`, `tb`). */
  currency: string;
  /** Invoice amount in millisatoshis. */
  amountMsat: bigint;
  /** Creation time, Unix seconds. */
  timestamp: number;
  /** Expiry in seconds (BOLT11 default 3600 when the `x` field is absent). */
  expirySeconds: number;
  /** Payment hash, 64 lowercase hex characters. */
  paymentHash: string;
  /** Every valid `h` (description hash) field, lowercase hex. */
  descriptionHashes: string[];
  /** Number of `d` (inline description) fields. */
  inlineDescriptionCount: number;
  /** Signing node public key (compressed, lowercase hex), from `n` or recovered. */
  payee: string;
  /** Whether the invoice carried an explicit `n` field. */
  hasPayeeField: boolean;
}

const SIGNATURE_WORDS = 104;
const TIMESTAMP_WORDS = 7;
const DEFAULT_EXPIRY_SECONDS = 3600;
const MSAT_PER_BTC = 100_000_000_000n;

// Multiplier → (numerator, denominator) of BTC; amount * BTC_in_msat * num / den.
const MULTIPLIERS: Record<string, bigint> = {
  m: 1_000n, // milli: 1e-3 BTC = 1e8 msat
  u: 1_000_000n,
  n: 1_000_000_000n,
  p: 1_000_000_000_000n,
};

const TAG = { p: 1, s: 16, d: 13, h: 23, x: 6, n: 19 } as const;

/**
 * Decodes a BOLT11 invoice and verifies its signature.
 *
 * Strict: rejects mixed case, a `lightning:` prefix, a missing or zero amount,
 * sub-millisatoshi amounts, amounts with leading zeros, a missing or duplicated
 * payment hash, a missing payment secret, and an invalid signature.
 *
 * @param invoice - BOLT11 invoice text
 * @returns The decoded invoice
 * @throws Error when the invoice is malformed or its signature is invalid
 */
export function decodeInvoice(invoice: string): DecodedInvoice {
  if (typeof invoice !== "string" || invoice.length === 0) throw new Error("empty invoice");
  const { prefix, words } = bech32.decode(invoice as `${string}1${string}`, false);
  const { currency, amountMsat } = parseHrp(prefix);

  if (words.length < TIMESTAMP_WORDS + SIGNATURE_WORDS) throw new Error("invoice too short");
  const signed = words.slice(0, words.length - SIGNATURE_WORDS);
  const sigBytes = bech32.fromWords(words.slice(words.length - SIGNATURE_WORDS));
  const timestamp = wordsToNumber(signed.slice(0, TIMESTAMP_WORDS));

  const fields = parseTaggedFields(signed.slice(TIMESTAMP_WORDS));
  if (fields.paymentHashes.length !== 1) throw new Error("invoice needs exactly one payment hash");
  if (fields.paymentSecrets !== 1) throw new Error("invoice needs exactly one payment secret");
  if (fields.payees.length > 1) throw new Error("invoice has more than one payee field");

  const prefixBytes = new TextEncoder().encode(prefix);
  const dataBytes = Uint8Array.from(scure.convertRadix2(signed, 5, 8, true));
  const message = new Uint8Array(prefixBytes.length + dataBytes.length);
  message.set(prefixBytes);
  message.set(dataBytes, prefixBytes.length);
  const digest = sha256(message);

  const payee = verifySignature(sigBytes, digest, fields.payees[0]);

  return {
    currency,
    amountMsat,
    timestamp,
    expirySeconds: fields.expiry ?? DEFAULT_EXPIRY_SECONDS,
    paymentHash: fields.paymentHashes[0],
    descriptionHashes: fields.descriptionHashes,
    inlineDescriptionCount: fields.inlineDescriptions,
    payee,
    hasPayeeField: fields.payees.length === 1,
  };
}

/**
 * Parses the human-readable part into currency and millisatoshi amount.
 *
 * @param prefix - The bech32 human-readable part
 * @returns Currency prefix and amount in millisatoshis
 */
function parseHrp(prefix: string): { currency: string; amountMsat: bigint } {
  const match = /^ln([a-z]+?)([0-9]+)?([munp])?$/.exec(prefix);
  if (!match) throw new Error("invalid invoice prefix");
  const [, currency, digits, multiplier] = match;
  if (!digits) throw new Error("invoice has no amount");
  if (digits.length > 1 && digits.startsWith("0")) throw new Error("amount has leading zeros");
  const value = BigInt(digits);
  if (value === 0n) throw new Error("invoice amount is zero");
  if (!multiplier) return { currency, amountMsat: value * MSAT_PER_BTC };
  const scaled = value * MSAT_PER_BTC;
  const divisor = MULTIPLIERS[multiplier];
  if (scaled % divisor !== 0n) throw new Error("amount is not an integral millisatoshi");
  return { currency, amountMsat: scaled / divisor };
}

interface TaggedFields {
  paymentHashes: string[];
  paymentSecrets: number;
  descriptionHashes: string[];
  inlineDescriptions: number;
  payees: string[];
  expiry?: number;
}

/**
 * Reads BOLT11 tagged fields, skipping unknown fields and wrong-length known
 * fields as BOLT11 requires.
 *
 * @param words - 5-bit words after the timestamp, before the signature
 * @returns The fields the scheme consumes
 */
function parseTaggedFields(words: number[]): TaggedFields {
  const out: TaggedFields = {
    paymentHashes: [],
    paymentSecrets: 0,
    descriptionHashes: [],
    inlineDescriptions: 0,
    payees: [],
  };
  let i = 0;
  while (i < words.length) {
    if (i + 3 > words.length) throw new Error("truncated tagged field");
    const tag = words[i];
    const length = words[i + 1] * 32 + words[i + 2];
    const data = words.slice(i + 3, i + 3 + length);
    if (data.length !== length) throw new Error("truncated tagged field");
    i += 3 + length;

    switch (tag) {
      case TAG.p:
        if (length === 52) out.paymentHashes.push(bytesToHex(bech32.fromWords(data)));
        break;
      case TAG.s:
        if (length === 52) out.paymentSecrets += 1;
        break;
      case TAG.h:
        if (length === 52) out.descriptionHashes.push(bytesToHex(bech32.fromWords(data)));
        break;
      case TAG.d:
        out.inlineDescriptions += 1;
        break;
      case TAG.n:
        if (length === 53) out.payees.push(bytesToHex(bech32.fromWords(data)));
        break;
      case TAG.x:
        if (out.expiry !== undefined) throw new Error("duplicate expiry field");
        out.expiry = wordsToNumber(data);
        break;
      default:
        break;
    }
  }
  return out;
}

/**
 * Verifies the invoice signature against `n` when present, otherwise recovers
 * the signing key.
 *
 * @param sigBytes - 65 bytes: compact signature followed by the recovery id
 * @param digest - SHA-256 of the signed invoice bytes
 * @param payeeField - Public key from the `n` field, if present
 * @returns The signing public key, compressed lowercase hex
 */
function verifySignature(sigBytes: Uint8Array, digest: Uint8Array, payeeField?: string): string {
  if (sigBytes.length !== 65) throw new Error("invalid signature length");
  const recovery = sigBytes[64];
  if (recovery > 3) throw new Error("invalid recovery id");
  const compact = sigBytes.slice(0, 64);
  const signature = secp256k1.Signature.fromCompact(compact);
  if (payeeField !== undefined) {
    if (!secp256k1.verify(compact, digest, hexToBytes(payeeField), { lowS: false })) {
      throw new Error("invalid invoice signature");
    }
    return payeeField;
  }
  const recovered = signature.addRecoveryBit(recovery).recoverPublicKey(digest);
  const key = recovered.toRawBytes(true);
  if (!secp256k1.verify(compact, digest, key, { lowS: false })) {
    throw new Error("invalid invoice signature");
  }
  return bytesToHex(key);
}

/**
 * Interprets 5-bit words as a big-endian unsigned integer.
 *
 * @param words - 5-bit words
 * @returns The integer value
 */
function wordsToNumber(words: number[]): number {
  let value = 0;
  for (const word of words) {
    value = value * 32 + word;
    if (!Number.isSafeInteger(value)) throw new Error("integer field too large");
  }
  return value;
}
