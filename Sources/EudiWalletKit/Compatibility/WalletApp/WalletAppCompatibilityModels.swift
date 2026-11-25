//
//  WalletAppCompatibilityModels.swift
//  EudiWalletKit
//

import Foundation
import JOSESwift
import OpenID4VCI
import Security

public protocol WalletAttestationsProviderForWalletAppCompatibility: WalletAttestationsProvider {
	func getKeysAttestation(docType: String) async throws -> String?
}

public struct IssuerDPoPConstructorParam: @unchecked Sendable {
	public let clientID: String?
	public let expirationDuration: TimeInterval?
	public let aud: String?
	public let jti: String?
	public let jwk: JWK
	public let privateKey: SecKey

	public init(clientID: String?, expirationDuration: TimeInterval?, aud: String?, jti: String?, jwk: JWK, privateKey: SecKey) {
		self.clientID = clientID
		self.expirationDuration = expirationDuration
		self.aud = aud
		self.jti = jti
		self.jwk = jwk
		self.privateKey = privateKey
	}
}

/// Lifetime of the authorization behind a refresh token: when the token response that returned the
/// refresh token was received, and that time plus its `authorization_expires_in`.
/// Captured once at issuance and carried over when credentials are re-issued with the refresh token.
public struct AuthorizationLifetime: Codable, Sendable, Equatable {
	public let issuedAt: Date
	public let expiresAt: Date?

	public init(issuedAt: Date, expiresAt: Date?) {
		self.issuedAt = issuedAt
		self.expiresAt = expiresAt
	}

	init?(authorized: AuthorizedRequest) {
		guard let refreshToken = authorized.refreshToken, refreshToken.refreshToken != nil else { return nil }
		let issuedAt = Date(timeIntervalSinceReferenceDate: authorized.timeStamp)
		self.init(issuedAt: issuedAt, expiresAt: refreshToken.authorizationExpiresIn.map { issuedAt.addingTimeInterval($0) })
	}
}

enum AuthorizationLifetimeSource: Sendable {
	case authorization
	case inherited(AuthorizationLifetime?)

	func lifetime(for authorized: AuthorizedRequest) -> AuthorizationLifetime? {
		switch self {
		case .authorization: AuthorizationLifetime(authorized: authorized)
		case .inherited(let lifetime): lifetime
		}
	}
}

public struct AuthorizedRequestParams: Sendable {
	public let accessToken: String?
	public let refreshToken: String?
	public let timeStamp: TimeInterval
	public let tokenType: TokenType?
	public let accessTokenExpiresIn: TimeInterval?
	public let refreshTokenExpiresIn: TimeInterval?
	public let authorizationLifetime: AuthorizationLifetime?

	public init(accessToken: String, refreshToken: String?, timeStamp: TimeInterval, tokenType: TokenType? = .dpop, accessTokenExpiresIn: TimeInterval? = nil, refreshTokenExpiresIn: TimeInterval? = nil, authorizationLifetime: AuthorizationLifetime? = nil) {
		self.accessToken = accessToken
		self.refreshToken = refreshToken
		self.timeStamp = timeStamp
		self.tokenType = tokenType
		self.accessTokenExpiresIn = accessTokenExpiresIn
		self.refreshTokenExpiresIn = refreshTokenExpiresIn
		self.authorizationLifetime = authorizationLifetime
	}

	public init(from authorized: AuthorizedRequest, authorizationLifetime: AuthorizationLifetime? = nil) {
		self.accessToken = authorized.accessToken.accessToken
		self.refreshToken = authorized.refreshToken?.refreshToken
		self.timeStamp = authorized.timeStamp
		self.tokenType = authorized.accessToken.tokenType
		self.accessTokenExpiresIn = authorized.accessToken.expiresIn
		self.refreshTokenExpiresIn = authorized.refreshToken?.expiresIn
		self.authorizationLifetime = authorizationLifetime
	}

	public func toAuthorizedRequest() throws -> AuthorizedRequest {
		guard let accessToken, !accessToken.isEmpty else {
			throw RefreshAuthorizationError.missingAccessToken
		}
		let issuanceAccessToken = try IssuanceAccessToken(accessToken: accessToken, tokenType: tokenType, expiresIn: accessTokenExpiresIn ?? .zero)
		var issuanceRefreshToken: IssuanceRefreshToken?
		if let refreshToken {
			issuanceRefreshToken = try IssuanceRefreshToken(refreshToken: refreshToken, expiresIn: refreshTokenExpiresIn)
		}
		return AuthorizedRequest(accessToken: issuanceAccessToken, refreshToken: issuanceRefreshToken, credentialIdentifiers: nil, timeStamp: timeStamp, dPopNonce: nil, grantType: nil)
	}
}

/// Carried in `KeyOptions.additionalOptions` when the wallet app creates its refresh-token DPoP key, so the
/// secure area can attest the key with the authorization server's DPoP nonce instead of a credential nonce.
public struct DPoPKeyCreationOptions: Codable, Sendable, Equatable {
	public static let dpopPurpose = "dpop"

	public let purpose: String
	public let authorizationServerNonce: String?

	enum CodingKeys: String, CodingKey {
		case purpose
		case authorizationServerNonce = "authorization_server_nonce"
	}

	public init(authorizationServerNonce: String?) {
		self.purpose = Self.dpopPurpose
		self.authorizationServerNonce = authorizationServerNonce
	}

	/// The options carried in `additionalOptions`, or `nil` when they don't describe a DPoP key.
	public static func decode(_ additionalOptions: Data?) -> DPoPKeyCreationOptions? {
		guard let additionalOptions, let options = try? JSONDecoder().decode(Self.self, from: additionalOptions),
			  options.purpose == dpopPurpose else { return nil }
		return options
	}
}

/// Errors thrown by the refresh-token based credential re-issuance flow.
public enum RefreshAuthorizationError: LocalizedError {
	/// No (or empty) access token was provided; nothing to refresh from.
	case missingAccessToken
	/// The authorization server rejected the refresh token (4xx); a full re-authorization is required.
	case reauthorizationRequired(statusCode: Int, description: String)

	public var errorDescription: String? {
		switch self {
		case .missingAccessToken:
			return "No stored access token available to refresh authorization"
		case .reauthorizationRequired(let statusCode, let description):
			return "Refresh token rejected with status \(statusCode); full re-authorization required. \(description)"
		}
	}
}
