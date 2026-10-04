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
   * specification hashes the bytes as received. With Express, capture them
   * with `express.raw()` or a `verify` callback.
   */
  rawBody?: (context: HTTPTransportContext) => Uint8Array | undefined;
}

/**
 * Builds the server's `requestBinding` for HTTP resources.
 *
 * @param config - Public origin, bound headers, and raw-body accessor
 * @returns A binding function for {@link ExactLnbtcServerOptions.requestBinding}
 */
export function httpTransportBinding(config: HttpTransportBindingConfig): ServerRequestBinding {
  const origin = config.publicOrigin.replace(/\/+$/, "");
  return transportContext => {
    const context = transportContext as HTTPTransportContext | undefined;
    const adapter = context?.request?.adapter;
    if (!context || !adapter) throw new LnbtcError(Errors.requestBinding);
    return httpRequestBinding({
      method: adapter.getMethod(),
      url: origin + requestTarget(adapter.getUrl()),
      body: config.rawBody?.(context) ?? new Uint8Array(),
      boundHeaders: config.boundHeaders ?? [],
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
 * Extracts the raw request target (path and query) from an absolute URL
 * without normalizing it.
 *
 * @param url - Absolute request URL
 * @returns The path and query, starting with `/`
 */
function requestTarget(url: string): string {
  const authorityStart = url.indexOf("://");
  const pathStart = authorityStart < 0 ? -1 : url.indexOf("/", authorityStart + 3);
  if (pathStart < 0) return "/";
  return url.slice(pathStart).replace(/#.*$/, "");
}
