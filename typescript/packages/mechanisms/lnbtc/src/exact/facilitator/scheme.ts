import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
  SchemeNetworkFacilitator,
  SettleResponse,
  VerifyResponse,
} from "@x402/core/types";
import { bindingsEqual, parseBindingExtra } from "../../binding";
import {
  ASSET_TRANSFER_METHOD,
  CAIP_FAMILY,
  DEFAULT_CLOCK_SKEW_SECONDS,
  Errors,
  LNBTC_NETWORKS,
  LnbtcError,
  PAYMENT_FLOW,
  REPLAY_RETENTION_SECONDS,
  SCHEME,
} from "../../constants";
import { canonicalize } from "../../jcs";
import type { Clock, ReplayStore } from "../../types";
import {
  reject,
  unixNow,
  validateCoreTerms,
  validateInvoice,
  validateMethodAndFlow,
  validateSkew,
} from "../../validation";

/**
 * Options for the lnbtc facilitator.
 */
export interface ExactLnbtcFacilitatorOptions {
  /** Restart-durable replay store shared by every instance settling for a receiver. */
  replayStore: ReplayStore;
  /** Clock-skew allowance in seconds (default 60). */
  clockSkewSeconds?: number;
  /** Clock returning Unix seconds. */
  clock?: Clock;
  /** Supported networks mapped to BOLT11 currency (default: mainnet and testnet). */
  networks?: Readonly<Record<string, string>>;
}

// Extra fields checked by dedicated rules rather than the generic equality rule.
const SCHEME_EXTRA_FIELDS = new Set([
  "assetTransferMethod",
  "paymentFlow",
  "invoice",
  "requestHash",
  "requestBindingProfile",
  "requestBindingParams",
]);

/**
 * Facilitator for `exact` on `lnbtc`: verifies the preimage locally against the
 * accepted invoice and consumes the payment hash. Needs no receiver access.
 */
export class ExactLnbtcScheme implements SchemeNetworkFacilitator {
  readonly scheme = SCHEME;
  readonly caipFamily = CAIP_FAMILY;
  private readonly replayStore: ReplayStore;
  private readonly skew: number;
  private readonly clock: Clock;
  private readonly networks: Readonly<Record<string, string>>;

  /**
   * Creates the facilitator scheme.
   *
   * @param options - Replay store, clock, skew, and networks
   */
  constructor(options: ExactLnbtcFacilitatorOptions) {
    const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
    validateSkew(skew);
    this.replayStore = options.replayStore;
    this.skew = skew;
    this.clock = options.clock ?? unixNow;
    this.networks = options.networks ?? LNBTC_NETWORKS;
  }

  /**
   * Advertises the only supported transfer method and flow.
   *
   * @param network - Network identifier
   * @returns Supported-kind extra
   */
  getExtra(network: Network): Record<string, unknown> | undefined {
    if (!(network in this.networks)) return undefined;
    return { assetTransferMethod: ASSET_TRANSFER_METHOD, paymentFlow: PAYMENT_FLOW };
  }

  /**
   * Lightning settlement uses no facilitator signers.
   *
   * @param _network - Network identifier
   * @returns An empty list
   */
  getSigners(_network: string): string[] {
    return [];
  }

  /**
   * The `upfront` flow does not use `/verify`.
   *
   * @param _payload - Payment payload
   * @param _requirements - Payment requirements
   * @returns An invalid result with the payment-flow reason
   */
  async verify(
    _payload: PaymentPayload,
    _requirements: PaymentRequirements,
  ): Promise<VerifyResponse> {
    return { isValid: false, invalidReason: Errors.paymentFlow };
  }

  /**
   * Validates the proof in specification order, then atomically consumes
   * `network:payment_hash`.
   *
   * @param payload - Payment payload carrying `accepted` and the preimage
   * @param requirements - Server-computed requirements, including the expected request hash
   * @returns The settlement result; `transaction` is the payment hash
   */
  async settle(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<SettleResponse> {
    const network = requirements.network;
    const now = this.clock();
    let key: string;
    let paymentHash: string;
    let retainUntil: number;
    try {
      const accepted = payload.accepted;
      matchCoreFields(accepted, requirements);
      validateCoreTerms(requirements, this.networks);
      validateCoreTerms(accepted, this.networks);
      const expected = this.matchExtra(accepted, requirements);

      if (!isNonEmptyString(requirements.extra?.invoice)) reject(Errors.invoiceMissing);
      if (!isNonEmptyString(accepted.extra?.invoice)) reject(Errors.invoiceMissing);
      const invoice = validateInvoice(
        accepted.extra.invoice,
        requirements,
        expected,
        this.networks,
        {
          now,
          skew: this.skew,
          expiry: "settlement",
        },
      );

      validatePreimage(payload.payload?.preimage, invoice.paymentHash);
      paymentHash = invoice.paymentHash;
      key = `${network}:${paymentHash}`;
      retainUntil =
        invoice.timestamp + invoice.expirySeconds + this.skew + REPLAY_RETENTION_SECONDS;
    } catch (error) {
      if (error instanceof LnbtcError) return failure(error.reason, network);
      throw error;
    }

    if (!(await this.replayStore.consume(key, retainUntil))) {
      return failure(Errors.duplicateSettlement, network);
    }
    return { success: true, transaction: paymentHash, network };
  }

  /**
   * Step 3: transfer method, flow, request binding, and other declared extras.
   *
   * @param accepted - Client-echoed requirements
   * @param requirements - Server-computed requirements
   * @returns The expected request hash
   */
  private matchExtra(accepted: PaymentRequirements, requirements: PaymentRequirements): string {
    validateMethodAndFlow(requirements.extra);
    validateMethodAndFlow(accepted.extra);
    const expected = parseBindingExtra(requirements.extra);
    const echoed = parseBindingExtra(accepted.extra);
    if (!bindingsEqual(expected, echoed)) reject(Errors.requestMismatch);

    for (const [field, value] of Object.entries(requirements.extra ?? {})) {
      if (SCHEME_EXTRA_FIELDS.has(field)) continue;
      if (!(field in (accepted.extra ?? {})) || !jcsEqual(value, accepted.extra[field])) {
        reject(Errors.extraMismatch);
      }
    }
    return expected.requestHash;
  }
}

/**
 * Step 1: the echoed core fields equal the requirements.
 *
 * @param accepted - Client-echoed requirements
 * @param requirements - Server-computed requirements
 */
function matchCoreFields(accepted: PaymentRequirements, requirements: PaymentRequirements): void {
  if (!accepted) reject(Errors.unsupportedScheme);
  if (accepted.scheme !== requirements.scheme) reject(Errors.unsupportedScheme);
  if (accepted.network !== requirements.network) reject(Errors.networkMismatch);
  if (accepted.amount !== requirements.amount) reject(Errors.amountMismatch);
  if (accepted.asset !== requirements.asset) reject(Errors.asset);
  if (accepted.payTo !== requirements.payTo) reject(Errors.payToMismatch);
  if (accepted.maxTimeoutSeconds !== requirements.maxTimeoutSeconds) {
    reject(Errors.maxTimeoutMismatch);
  }
}

/**
 * Step 6: the preimage is 32 bytes of lowercase hex hashing to the payment hash.
 *
 * @param preimage - Candidate preimage
 * @param paymentHash - Invoice payment hash, lowercase hex
 */
function validatePreimage(preimage: unknown, paymentHash: string): void {
  if (preimage === undefined || preimage === null) reject(Errors.preimageMissing);
  if (typeof preimage !== "string" || !/^[0-9a-f]*$/.test(preimage)) {
    reject(Errors.preimageMalformed);
  }
  if (preimage.length !== 64) reject(Errors.preimageLength);
  if (bytesToHex(sha256(hexToBytes(preimage))) !== paymentHash) {
    reject(Errors.preimageHashMismatch);
  }
}

/**
 * Compares two JSON values by their JCS serialization.
 *
 * @param a - Left value
 * @param b - Right value
 * @returns Whether they serialize identically
 */
function jcsEqual(a: unknown, b: unknown): boolean {
  try {
    return canonicalize(a) === canonicalize(b);
  } catch {
    return false;
  }
}

/**
 * Checks for a non-empty string.
 *
 * @param value - Candidate
 * @returns Whether it is a non-empty string
 */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/**
 * Builds a failed settlement response.
 *
 * @param reason - Stable error reason
 * @param network - Requirements network
 * @returns The settlement response
 */
function failure(reason: string, network: Network): SettleResponse {
  return { success: false, errorReason: reason, transaction: "", network };
}
