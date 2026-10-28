---
"@x402/evm": patch
---

Fixed exact EVM verify and settle throwing on a malformed payload. Both now return `invalid_payload` when the EIP-3009 or Permit2 authorization is missing or the wrong shape.
