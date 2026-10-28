---
"@x402/evm": patch
---

Reject ERC-6492 wrappers whose factory calldata is empty. `classifyErc6492Payer` treats viem's `"0x"` as no deployment info, so exact verify returns `invalid_exact_evm_signature` instead of accepting a payment that settle cannot broadcast. v1 exact verify and auth-capture collect use the same helper.
