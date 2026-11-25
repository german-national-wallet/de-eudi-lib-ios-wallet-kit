import Testing
import Foundation
import OpenID4VCI
@testable import EudiWalletKit

@Suite("Authorization lifetime")
struct AuthorizationLifetimeTests {

	private static let issuedAt: TimeInterval = 800_000_000

	private func authorized(refreshToken: String?, authorizationExpiresIn: TimeInterval?, timeStamp: TimeInterval = issuedAt) throws -> AuthorizedRequest {
		AuthorizedRequest(
			accessToken: try IssuanceAccessToken(accessToken: "access", tokenType: .dpop, expiresIn: 300),
			refreshToken: try IssuanceRefreshToken(refreshToken: refreshToken, authorizationExpiresIn: authorizationExpiresIn),
			credentialIdentifiers: nil,
			timeStamp: timeStamp,
			dPopNonce: nil,
			grantType: nil
		)
	}

	private func roundTrip(_ data: AuthorizedRequestData) throws -> AuthorizedRequestData {
		try JSONDecoder().decode(AuthorizedRequestData.self, from: JSONEncoder().encode(data))
	}

	@Test func capturesTokenResponseTimeAndAuthorizationExpiry() throws {
		let data = try roundTrip(AuthorizedRequestData(from: authorized(refreshToken: "refresh", authorizationExpiresIn: 86_400)))

		let issued = Date(timeIntervalSinceReferenceDate: Self.issuedAt)
		#expect(data.authorizationLifetime == AuthorizationLifetime(issuedAt: issued, expiresAt: issued.addingTimeInterval(86_400)))
	}

	@Test func keepsIssueTimeWhenTheServerSendsNoAuthorizationExpiry() throws {
		let data = AuthorizedRequestData(from: try authorized(refreshToken: "refresh", authorizationExpiresIn: nil))

		#expect(data.authorizationLifetime?.issuedAt == Date(timeIntervalSinceReferenceDate: Self.issuedAt))
		#expect(data.authorizationLifetime?.expiresAt == nil)
	}

	@Test func hasNoLifetimeWithoutARefreshToken() throws {
		let data = AuthorizedRequestData(from: try authorized(refreshToken: nil, authorizationExpiresIn: 86_400))

		#expect(data.authorizationLifetime == nil)
	}

	@Test func refreshedAuthorizationKeepsTheInheritedLifetime() throws {
		let original = AuthorizationLifetime(issuedAt: Date(timeIntervalSinceReferenceDate: Self.issuedAt), expiresAt: nil)
		let refreshed = try authorized(refreshToken: "rotated", authorizationExpiresIn: 3_600, timeStamp: Self.issuedAt + 10_000)

		#expect(AuthorizedRequestData(from: refreshed, authorizationLifetime: .inherited(original)).authorizationLifetime == original)
		#expect(AuthorizedRequestData(from: refreshed, authorizationLifetime: .inherited(nil)).authorizationLifetime == nil)
	}

	@Test func dataStoredBeforeTheLifetimeExistedDecodesWithoutOne() throws {
		var json = try JSONSerialization.jsonObject(
			with: JSONEncoder().encode(AuthorizedRequestData(from: authorized(refreshToken: "refresh", authorizationExpiresIn: 86_400)))
		) as! [String: Any]
		json.removeValue(forKey: "authorizationLifetime")

		let data = try JSONDecoder().decode(AuthorizedRequestData.self, from: JSONSerialization.data(withJSONObject: json))

		#expect(data.authorizationLifetime == nil)
		#expect(data.refreshToken?.refreshToken == "refresh")
	}

	@Test func storedParamsCarryTheLifetimeThroughARefresh() throws {
		let lifetime = AuthorizationLifetime(issuedAt: Date(timeIntervalSinceReferenceDate: Self.issuedAt), expiresAt: nil)
		let refreshed = try authorized(refreshToken: "rotated", authorizationExpiresIn: nil, timeStamp: Self.issuedAt + 10_000)

		#expect(AuthorizedRequestParams(from: refreshed, authorizationLifetime: lifetime).authorizationLifetime == lifetime)
	}
}
