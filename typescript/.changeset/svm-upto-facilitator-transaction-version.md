---
"@x402/svm": patch
---

SVM upto: add `facilitatorTransactionVersion` (0 or 1) to `UptoSvmFacilitatorConfig` and `UptoSvmRentCleanupManagerConfig` to choose the message version of the claim, cancel, and rent-cleanup transactions the facilitator builds itself. Client-built versions are unaffected. Unset keeps v1.
