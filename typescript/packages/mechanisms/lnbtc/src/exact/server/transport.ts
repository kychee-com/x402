import type { HTTPTransportContext } from "@x402/core/http";
import { httpRequestBinding, mcpToolCallBinding } from "../../binding";
import { Errors, LnbtcError } from "../../constants";
import type { ServerRequestBinding } from "./scheme";

/**
 * Configuration for binding HTTP requests (`http:1`).
 */
export interface HttpTransportBindingConfig {
  /**
   * The resource's public origin, e.g. `https://api.example.com`. The request
   * target is appended to it; the `Host` header is never trusted.
   */
  publicOrigin: string;
  /** Lowercase names of every header that affects the purchased operation. */
  boundHeaders?: readonly string[];
  /**
   * Returns the raw request content bytes. Parsed bodies cannot be used: the
   * specification hashes the bytes as received. Defaults to the adapter's
   * body when it is bytes (for example after `express.raw()`).
   */
  rawBody?: (
    context: HTTPTransportContext,
  ) => Uint8Array | undefined | Promise<Uint8Array | undefined>;
}

// Adapters build their URL from these headers. A legitimate value never lets
// the client move the boundary between scheme, authority, and request target.
const URL_HEADER_RULES: ReadonlyArray<[string, RegExp]> = [
  ["host", /^[^/?#@\\\s,]+$/],
  ["x-forwarded-host", /^[^/?#@\\\s,]+$/],
  ["x-forwarded-proto", /^[A-Za-z][A-Za-z0-9+.-]*$/],
];

/**
 * Reads raw body bytes from the adapter. A request without content hashes as
 * empty; content that a parser already consumed is refused, because the
 * original bytes are gone.
 *
 * @param context - HTTP transport context
 * @returns The body bytes
 */
async function adapterRawBody(context: HTTPTransportContext): Promise<Uint8Array> {
  const adapter = context.request.adapter;
  const body = await adapter.getBody?.();
  if (body instanceof Uint8Array) return body;
  const length = adapter.getHeader("content-length");
  const hasContent =
    adapter.getHeader("transfer-encoding") !== undefined ||
    (length !== undefined && !/^\s*0+\s*$/.test(length)) ||
    !isEmptyParsedBody(body);
  if (!hasContent) return new Uint8Array();
  throw new TypeError(
    "lnbtc http:1 binding needs the raw request body bytes: mount a raw body parser " +
      "(e.g. express.raw()) for this route or pass rawBody",
  );
}

/**
 * Whether a parsed adapter body carries no content: absent, `null`, an empty
 * string, or an empty plain object (some parsers default the body to `{}`).
 *
 * @param body - Parsed body from the adapter
 * @returns Whether the body is empty
 */
function isEmptyParsedBody(body: unknown): boolean {
  if (body === undefined || body === null || body === "") return true;
  return (
    typeof body === "object" &&
    Object.getPrototypeOf(body) === Object.prototype &&
    Object.keys(body).length === 0
  );
}

/**
 * Builds the server's `requestBinding` for HTTP resources.
 *
 * @param config - Public origin, bound headers, and raw-body accessor
 * @returns A binding function for {@link ExactLnbtcServerOptions.requestBinding}
 * @throws LnbtcError `invalid_exact_lnbtc_request_binding` when the configured
 *   origin or bound headers are invalid
 */
export function httpTransportBinding(config: HttpTransportBindingConfig): ServerRequestBinding {
  const origin = config.publicOrigin.replace(/\/+$/, "");
  const boundHeaders = [...(config.boundHeaders ?? [])];
  if (/[?#]/.test(origin)) throw new LnbtcError(Errors.requestBinding);
  // Validates the origin and header configuration once, up front.
  httpRequestBinding({
    method: "GET",
    url: `${origin}/`,
    boundHeaders,
    getHeader: () => undefined,
  });

  return async transportContext => {
    const context = transportContext as HTTPTransportContext | undefined;
    const adapter = context?.request?.adapter;
    if (!context || !adapter) throw new LnbtcError(Errors.requestBinding);
    for (const [name, rule] of URL_HEADER_RULES) {
      const value = adapter.getHeader(name);
      // Proxies may append comma-separated hops; each must be well-formed.
      if (value !== undefined && !value.split(",").every(part => rule.test(part.trim()))) {
        throw new LnbtcError(Errors.requestBinding);
      }
    }
    const body = config.rawBody ? await config.rawBody(context) : await adapterRawBody(context);
    return httpRequestBinding({
      method: adapter.getMethod(),
      url: origin + requestTarget(adapter.getUrl()),
      body,
      boundHeaders,
      getHeader: name => adapter.getHeader(name),
    });
  };
}

/**
 * Configuration for binding MCP tool calls (`mcp:1`).
 */
export interface McpTransportBindingConfig {
  /** Configured absolute URI identifying this MCP server. */
  server: string;
  /** `_meta` member names that affect the purchased operation. */
  boundMetadata?: readonly string[];
}

/**
 * Builds the server's `requestBinding` for tools wrapped by `@x402/mcp`.
 *
 * @param config - Server identity and bound metadata names
 * @returns A binding function for {@link ExactLnbtcServerOptions.requestBinding}
 */
export function mcpTransportBinding(config: McpTransportBindingConfig): ServerRequestBinding {
  return transportContext => {
    const context = transportContext as
      | { toolName?: unknown; arguments?: unknown; meta?: unknown }
      | undefined;
    if (!context || typeof context.toolName !== "string") {
      throw new LnbtcError(Errors.requestBinding);
    }
    return mcpToolCallBinding({
      server: config.server,
      name: context.toolName,
      arguments: context.arguments,
      meta: context.meta,
      boundMetadata: config.boundMetadata ?? [],
    });
  };
}

/**
 * Extracts the raw request target (origin-form path and query) from the
 * adapter's absolute URL without normalizing it. The authority ends at the
 * first `/`, `?`, or `#`; a target that is not origin-form is refused rather
 * than repaired, and one carrying a fragment fails URI validation.
 *
 * @param url - Absolute request URL
 * @returns The path and query, starting with `/`
 * @throws LnbtcError `invalid_exact_lnbtc_request_binding` on an unusable target
 */
function requestTarget(url: string): string {
  const schemeEnd = url.indexOf("://");
  if (schemeEnd < 0) throw new LnbtcError(Errors.requestBinding);
  const rest = url.slice(schemeEnd + 3);
  const authorityEnd = rest.search(/[/?#]/);
  if (authorityEnd < 0) return "/";
  const target = rest.slice(authorityEnd);
  // A fragment left in the target fails URI validation in httpRequestBinding.
  if (!target.startsWith("/") || target.startsWith("//")) {
    throw new LnbtcError(Errors.requestBinding);
  }
  return target;
}
