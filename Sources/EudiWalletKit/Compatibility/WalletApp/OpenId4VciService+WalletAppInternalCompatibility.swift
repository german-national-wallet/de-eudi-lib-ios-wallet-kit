//
//  OpenId4VciService+WalletAppInternalCompatibility.swift
//  EudiWalletKit
//

import Foundation
import OpenID4VCI
import JOSESwift

extension OpenId4VCIService {
	func makeBindingKeyForWalletAppCompatibility(
		publicKeyJWK: ECPublicKey,
		algType: JWSAlgorithm.AlgorithmType,
		signer: SecureAreaSigner,
		funcKeyAttestationJWT: FuncKeyAttestationJWT?
	) throws -> BindingKey {
		_ = funcKeyAttestationJWT
		return .jwt(
			algorithm: JWSAlgorithm(algType),
			jwk: publicKeyJWK,
			privateKey: .custom(signer),
			issuer: config.clientId
		)
	}

	func getKeyAttestationJWTForWalletAppCompatibility(_ publicKeys: [ECPublicKey], nonce: String?) async throws -> KeyAttestationJWT {
		guard let additionalOptions = issueReq.keyOptions?.additionalOptions else {
			throw PresentationSession.makeError(str: "additionalOptions not found")
		}
		guard let docType = String(data: additionalOptions, encoding: .utf8),
			  let wte = UserDefaults.standard.string(forKey: docType) else {
			throw PresentationSession.makeError(str: "wte not found")
		}
		let keyAttestationJwt: KeyAttestationJWT = try .init(jws: .init(compactSerialization: wte))
		return keyAttestationJwt
	}
}
