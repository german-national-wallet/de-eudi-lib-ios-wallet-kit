# Lean 4 verification model

This directory contains a small, executable Lean 4 specification of the
security-critical pure decisions in the issuance flow. Lean does not compile
or verify the Swift runtime, so these proofs are deliberately limited to logic
that can be represented without I/O, cryptography, Keychain access, or actor
scheduling.

Run the proof checker from this directory:

```sh
lake env lean EudiWalletKitVerification.lean
```

## Traceability

| Lean model | Swift implementation | Runtime guard |
| --- | --- | --- |
| `ValidBatchSize` / `acceptsBatchSize` | `OpenId4VciService.validateBatchSize` | `Invalid credential batch sizes are rejected` |
| `authorizeState` | `OpenId4VciService.validateAuthorizationState` | `Pending issuance requires the original OAuth state` |
| `pairResponses` | `OpenId4VciService.pairCredentialPayloadsWithPublicKeys` | `Credential and binding-key counts must match` |
| `acquireLease` | `IssuanceResumeLeaseRegistry.acquire` | `Concurrent issuance resumes are rejected` |

The Lean proofs establish the stated invariants for the model. Swift unit tests
are the executable correspondence check for the current implementation.
