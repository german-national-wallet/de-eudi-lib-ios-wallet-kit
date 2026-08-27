//
//  OpenId4VciService+WalletAppInternalCompatibility.swift
//  EudiWalletKit
//

import Foundation
import OpenID4VCI
import JOSESwift

extension OpenId4VciService {
	func attachKeyAttestation(to constructor: DPoPConstructor?) async -> DPoPConstructorType? {
		guard let constructor else { return constructor }
		let provider = config.keyAttestationsConfig.walletAttestationsProvider
		do {
			let wte = try await provider.getKeysAttestation(keys: [constructor.jwk], nonce: nil)
			let keyAttestationJWT = try KeyAttestationJWT(jwt: wte)
			return KeyAttestedDPoPConstructor(wrapping: constructor, keyAttestation: keyAttestationJWT)
		} catch {
			logger.info("No key attestation available for the DPoP key, sending an unattested DPoP proof: \(error)")
			return constructor
		}
	}
}
