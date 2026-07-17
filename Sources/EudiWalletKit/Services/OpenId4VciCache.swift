import Foundation
import OpenID4VCI

/// Wallet-owned cache for credential offers.
///
/// Offer objects can contain authorization-server and issuer metadata resolved under a
/// caller-selected trust policy. Keeping this cache wallet-scoped prevents one wallet
/// or test instance from reusing another wallet's resolved security context.
final class OpenId4VciCache: @unchecked Sendable {
	private let lock = NSLock()
	private var credentialOffers: [String: CredentialOffer] = [:]

	func credentialOffer(for key: String) -> CredentialOffer? {
		lock.withLock { credentialOffers[key] }
	}

	/// Atomically consumes a previously resolved one-time offer.
	func takeCredentialOffer(for key: String) -> CredentialOffer? {
		lock.withLock { credentialOffers.removeValue(forKey: key) }
	}

	func store(_ offer: CredentialOffer, for key: String) {
		lock.withLock { credentialOffers[key] = offer }
	}

	func removeCredentialOffer(for key: String) {
		lock.withLock { _ = credentialOffers.removeValue(forKey: key) }
	}

	func removeAllCredentialOffers() {
		lock.withLock { credentialOffers.removeAll() }
	}
}
