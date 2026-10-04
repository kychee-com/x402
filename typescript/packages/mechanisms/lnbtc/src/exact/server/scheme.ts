import type {
  AssetAmount,
  MoneyParser,
  Network,
  PaymentFlowConfig,
  PaymentPayload,
  PaymentRequirements,
  Price,
  SchemeNetworkServer,
  SchemePaymentRequiredContext,
  SupportedKind,
} from "@x402/core/types";
import { decodePaymentSignatureHeader, type HTTPTransportContext } from "@x402/core/http";
import type { RequestBinding } from "../../binding";
import {
  ASSET,
  ASSET_TRANSFER_METHOD,
  DEFAULT_CLOCK_SKEW_SECONDS,
  DYNAMIC_EXTRA_FIELDS,
  Errors,
  LNBTC_NETWORKS,
  PAYMENT_FLOW,
  SCHEME,
} from "../../constants";
import type { Clock, LightningReceiver } from "../../types";
import {
  reject,
  unixNow,
  validateInvoice,
  validateRequirements,
  validateSkew,
} from "../../validation";

/**
 * Computes the binding of the actual request from the transport context.
 * Use `httpTransportBinding` for HTTP; MCP servers supply the tool call.
 */
export type ServerRequestBinding = (
  transportContext: unknown,
) => RequestBinding | Promise<RequestBinding>;

/**
 * Options for the lnbtc resource server scheme.
 */
export interface ExactLnbtcServerOptions {
  /** Receiver node adapter with exclusive invoice-issuance authority for `payTo`. */
  receiver: LightningReceiver;
  /** Binding of the actual request, derived from server configuration. */
  requestBinding: ServerRequestBinding;
  /**
   * Called before each new invoice; return `false` to deny issuance
   * (`exact_lnbtc_invoice_issuance_denied`).
   */
  allowInvoice?: (transportContext: unknown) => boolean | Promise<boolean>;
  /** Clock-skew allowance in seconds (default 60). */
  clockSkewSeconds?: number;
  /** Clock returning Unix seconds. */
  clock?: Clock;
  /** Supported networks mapped to BOLT11 currency (default: mainnet and testnet). */
  networks?: Readonly<Record<string, string>>;
}

const SATS_PRICE = /^([0-9]+)(?:\.([0-9]+))? sats?$/;

/**
 * Resource server scheme for `exact` on `lnbtc`: binds each challenge to the
 * actual request and issues a fresh request-bound invoice.
 */
export class ExactLnbtcScheme implements SchemeNetworkServer {
  readonly scheme = SCHEME;
  readonly defaultAssetTransferMethod = ASSET_TRANSFER_METHOD;
  readonly paymentFlows: Readonly<Record<string, PaymentFlowConfig>> = {
    [ASSET_TRANSFER_METHOD]: { supported: [PAYMENT_FLOW], default: PAYMENT_FLOW },
  };
  readonly dynamicExtraFields = DYNAMIC_EXTRA_FIELDS;
  private readonly options: ExactLnbtcServerOptions;
  private readonly skew: number;
  private readonly clock: Clock;
  private readonly networks: Readonly<Record<string, string>>;
  private readonly moneyParsers: MoneyParser[] = [];

  /**
   * Creates the server scheme.
   *
   * @param options - Receiver adapter, request binding, and issuance policy
   */
  constructor(options: ExactLnbtcServerOptions) {
    const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
    validateSkew(skew);
    this.options = options;
    this.skew = skew;
    this.clock = options.clock ?? unixNow;
    this.networks = options.networks ?? LNBTC_NETWORKS;
  }

  /**
   * Registers a conversion for prices other than explicit millisatoshis or
   * `"N sat(s)"`, such as dollar prices. Parsers receive the raw price.
   *
   * @param parser - Conversion returning a BTC AssetAmount in msat, or null
   * @returns This scheme, for chaining
   */
  registerMoneyParser(parser: MoneyParser): ExactLnbtcScheme {
    this.moneyParsers.push(parser);
    return this;
  }

  /**
   * Converts a price to a BTC amount in millisatoshis.
   *
   * @param price - `{ asset: "BTC", amount: "<msat>" }`, `"21 sats"`, or a registered form
   * @param network - Network identifier
   * @returns The amount in millisatoshis
   */
  async parsePrice(price: Price, network: Network): Promise<AssetAmount> {
    if (!(network in this.networks)) reject(Errors.unsupportedNetwork);
    let result: AssetAmount | null = null;
    if (typeof price === "object" && price !== null) {
      result = price;
    } else if (typeof price === "string" && SATS_PRICE.test(price)) {
      result = { asset: ASSET, amount: satsToMsat(price) };
    } else {
      for (const parser of this.moneyParsers) {
        result = await parser(price, network);
        if (result) break;
      }
    }
    if (!result) {
      throw new Error(
        `Unsupported lnbtc price ${JSON.stringify(price)}: use an explicit AssetAmount ` +
          `{ asset: "BTC", amount: "<millisatoshis>" } or register a money parser`,
      );
    }
    if (result.asset !== ASSET) reject(Errors.asset);
    if (!/^[1-9][0-9]*$/.test(result.amount)) reject(Errors.amount);
    return { asset: ASSET, amount: result.amount };
  }

  /**
   * Sets the transfer method and payment flow. The request binding and invoice
   * are added per request in {@link enrichPaymentRequiredResponse}.
   *
   * @param requirements - Base requirements
   * @param _supportedKind - Facilitator supported kind
   * @param _facilitatorExtensions - Facilitator extensions
   * @returns The requirements with method and flow set
   */
  async enhancePaymentRequirements(
    requirements: PaymentRequirements,
    _supportedKind: SupportedKind,
    _facilitatorExtensions: string[],
  ): Promise<PaymentRequirements> {
    return {
      ...requirements,
      extra: {
        ...requirements.extra,
        assetTransferMethod: ASSET_TRANSFER_METHOD,
        paymentFlow: PAYMENT_FLOW,
      },
    };
  }

  /**
   * Binds each lnbtc requirement to the actual request. On the paid retry it
   * reuses the client's accepted invoice instead of issuing a replacement; on
   * a challenge it issues a fresh request-bound invoice.
   *
   * @param ctx - Payment-required context with the transport context
   * @returns The enriched requirements
   */
  readonly enrichPaymentRequiredResponse = async (
    ctx: SchemePaymentRequiredContext,
  ): Promise<PaymentRequirements[]> => {
    const binding = await this.options.requestBinding(ctx.transportContext);
    const acceptedInvoice = paidRetryInvoice(ctx);
    const out: PaymentRequirements[] = [];
    for (const requirements of ctx.requirements) {
      if (requirements.scheme !== SCHEME || !(requirements.network in this.networks)) {
        out.push(requirements);
        continue;
      }
      const bound: PaymentRequirements = {
        ...requirements,
        extra: {
          ...requirements.extra,
          requestHash: binding.requestHash,
          requestBindingProfile: binding.requestBindingProfile,
          requestBindingParams: binding.requestBindingParams,
        },
      };
      bound.extra.invoice = acceptedInvoice ?? (await this.issueInvoice(bound, ctx));
      out.push(bound);
    }
    return out;
  };

  /**
   * Issues and checks a fresh invoice for bound requirements.
   *
   * @param requirements - Requirements with the request binding set
   * @param ctx - Payment-required context
   * @returns The BOLT11 invoice
   */
  private async issueInvoice(
    requirements: PaymentRequirements,
    ctx: SchemePaymentRequiredContext,
  ): Promise<string> {
    const binding = validateRequirements(requirements, this.networks);
    if (this.options.allowInvoice && !(await this.options.allowInvoice(ctx.transportContext))) {
      reject(Errors.issuanceDenied);
    }
    const invoice = await this.options.receiver.createInvoice({
      amountMsat: BigInt(requirements.amount),
      descriptionHash: binding.requestHash,
      expirySeconds: requirements.maxTimeoutSeconds,
      network: requirements.network,
    });
    validateInvoice(invoice, requirements, binding.requestHash, this.networks, {
      now: this.clock(),
      skew: this.skew,
      expiry: "unexpired",
    });
    return invoice;
  }
}

/**
 * Returns the accepted lnbtc invoice when this pass precedes settlement of a
 * paid retry: a payment header is present and no error is being reported.
 *
 * @param ctx - Payment-required context
 * @returns The accepted invoice, or undefined when a fresh one is needed
 */
function paidRetryInvoice(ctx: SchemePaymentRequiredContext): string | undefined {
  if (ctx.error !== undefined) return undefined;
  const transport = ctx.transportContext as
    | (HTTPTransportContext & { meta?: Record<string, unknown> })
    | undefined;
  const payload =
    ctx.paymentPayload ??
    decodeHeader(transport?.request?.paymentHeader) ??
    (transport?.meta?.["x402/payment"] as PaymentPayload | undefined);
  const invoice = payload?.accepted?.extra?.invoice;
  return payload?.accepted?.scheme === SCHEME && typeof invoice === "string" && invoice.length > 0
    ? invoice
    : undefined;
}

/**
 * Decodes a payment header, ignoring malformed input.
 *
 * @param header - `PAYMENT-SIGNATURE` header value
 * @returns The payload, or undefined
 */
function decodeHeader(header: string | undefined) {
  if (!header) return undefined;
  try {
    return decodePaymentSignatureHeader(header);
  } catch {
    return undefined;
  }
}

/**
 * Converts `"N sat(s)"` to millisatoshis with exact decimal arithmetic.
 *
 * @param price - Price string
 * @returns Millisatoshis as a decimal string
 */
function satsToMsat(price: string): string {
  const [, whole, fraction = ""] = SATS_PRICE.exec(price) as RegExpExecArray;
  if (fraction.length > 3 && /[1-9]/.test(fraction.slice(3))) reject(Errors.amount);
  const msat = BigInt(whole) * 1000n + BigInt((fraction.slice(0, 3) || "0").padEnd(3, "0"));
  if (msat === 0n) reject(Errors.amount);
  return msat.toString();
}
