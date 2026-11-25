# German Wallet-specific fork differences from upstream

This fork is based on `eu-digital-identity-wallet/eudi-lib-ios-wallet-kit`, with some changed files compared to upstream `main`. The fork mainly adds Wallet App compatibility helpers and adapts OpenID4VCI issuance behavior.

## Differences

### Wallet App compatibility layer

Added files under:

`Sources/EudiWalletKit/Compatibility/WalletApp/`

These expose compatibility APIs for the Wallet App, including:

- `EudiWallet.issuePAR(...)`
- `EudiWallet.resumePendingIssuanceDocuments(...)`
- Wallet-app-specific OpenID4VCI configuration helpers
- Wallet/app-specific attestation provider protocol
- Small compatibility models for DPoP, client attestation, and authorized request data

**Why we need this:**

The Wallet App needs APIs that are not directly exposed upstream, especially for PAR-based issuance, resuming pending issuance, and passing app-specific attestation/private-key data into OpenID4VCI flows.

### OpenID4VCI service extensions

Added `OpenId4VciService+WalletAppCompatibility.swift`, which implements:

- PAR issuance flow
- pending issuance resume flow
- credential refresh using refresh tokens
- issuer recreation with latest metadata
- handling array-based JSON credential responses
- app-specific DPoP and attestation support

**Why we need this:**

The German Wallet App needs to continue issuance after external authorization, refresh credentials, and support issuer-specific credential response formats and attestation flows.

### Key attestation behavior change

Modified `Sources/EudiWalletKit/Services/OpenId4VciService.swift`.

When key attestation is supported, the fork returns an `.attestation(...)` binding key instead of creating normal JWT binding keys.

**Why we need this:**

The Wallet App expects attestation-based proof handling for supported issuers, rather than the default upstream JWT binding-key behavior.

### Authorization lifetime for refresh-token issuance

Modified `Sources/EudiWalletKit/Extensions.swift` (`AuthorizedRequestData`, `convertToDocMetadata`) and `Sources/EudiWalletKit/Services/OpenId4VciService.swift` (`authorizationLifetimeSource`, used in `finalizeIssuing`).

`AuthorizedRequestData` stores an `AuthorizationLifetime`: when the token response that returned the refresh token was received, and that time plus `authorization_expires_in`. Credentials re-issued through the compatibility refresh flow inherit the lifetime of the credentials they replace. `AuthorizedRequestParams.authorizationLifetime` and `EudiWallet.credentialSignedDate(docId:)` expose the dates to the app.

**Why we need this:**

The credential inspection screen shows the refresh token's lifetime for batch-issued credentials (including the PID), and the mdoc's `validityInfo.signed` otherwise. Upstream resets the token timestamp on every refresh and doesn't expose `signed`.

## Summary

The fork does not broadly change the wallet-kit architecture.  
Most differences are isolated compatibility extensions for the German Wallet App, focused on OpenID4VCI issuance, PAR, pending issuance resume, refresh-token issuance, DPoP, and key/wallet attestation.
