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
}
