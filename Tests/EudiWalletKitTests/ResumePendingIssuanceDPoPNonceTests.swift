import Testing
import Foundation
import OpenID4VCI
import JOSESwift
import MdocDataModel18013
@testable import EudiWalletKit

@Suite("Resume pending issuance authorization")
struct ResumePendingIssuanceDPoPNonceTests {

	private static let tokenEndpoint = URL(string: "https://issuer.example/token")!
	private static let state = "state-123"

	@Test func forwardsTheFinishAuthorizationNonceToTheFirstTokenRequest() async throws {
		let networking = TokenEndpointStub(responses: [.success])
		let request = try OpenId4VciService.makeResumeAuthorizationRequest(model: makePendingModel(), authorizePresentationUrl: Self.authorizeUrl, nonce: "finish-authorization-nonce", authorizationServerMetadata: .oauth(Self.authorizationServerMetadata()))

		_ = try await authorize(request: request, networking: networking)

		let proofs = await networking.dpopProofs
		#expect(proofs.count == 1)
		#expect(try nonceClaim(of: try #require(proofs.first)) == "finish-authorization-nonce")
	}

	@Test func withoutANonceTheLibraryStillRetriesWithTheServerNonce() async throws {
		let networking = TokenEndpointStub(responses: [.useDpopNonce("server-nonce"), .success])
		let request = try OpenId4VciService.makeResumeAuthorizationRequest(model: makePendingModel(), authorizePresentationUrl: Self.authorizeUrl, nonce: nil, authorizationServerMetadata: .oauth(Self.authorizationServerMetadata()))

		_ = try await authorize(request: request, networking: networking)

		let proofs = await networking.dpopProofs
		#expect(proofs.count == 2)
		#expect(try nonceClaim(of: proofs[0]) == nil)
		#expect(try nonceClaim(of: proofs[1]) == "server-nonce")
	}

	@Test func resumeRequestBindsTheAuthorizationServerIssuer() throws {
		let request = try resumeRequest(issSupported: true)

		#expect(request.expectedIssuer == URL(string: "https://issuer.example"))
		#expect(request.issParameterRequired)
	}

	@Test func acceptsAMatchingIss() async throws {
		let request = try resumeRequest(issSupported: true)

		_ = try await authorize(request: request, networking: TokenEndpointStub(responses: [.success]), iss: "https://issuer.example", issChecking: .ifSupported)
	}

	@Test func rejectsAMismatchingIss() async throws {
		let request = try resumeRequest(issSupported: false)

		await #expect {
			_ = try await authorize(request: request, networking: TokenEndpointStub(responses: [.success]), iss: "https://attacker.example", issChecking: .ifSupported)
		} throws: { error in
			guard case .issMismatch = error as? ValidationError else { return false }
			return true
		}
	}

	@Test func rejectsAMissingIssWhenTheServerAdvertisesSupport() async throws {
		let request = try resumeRequest(issSupported: true)

		await #expect {
			_ = try await authorize(request: request, networking: TokenEndpointStub(responses: [.success]), iss: nil, issChecking: .ifSupported)
		} throws: { error in
			guard case .issParameterRequiredButMissing = error as? ValidationError else { return false }
			return true
		}
	}

	@Test func allowsAMissingIssWhenTheServerDoesNotAdvertiseSupport() async throws {
		let request = try resumeRequest(issSupported: false)

		_ = try await authorize(request: request, networking: TokenEndpointStub(responses: [.success]), iss: nil, issChecking: .ifSupported)
	}

	private static let authorizeUrl = "https://issuer.example/authorize?client_id=wallet&request_uri=urn:example"

	private static func authorizationServerMetadata(issSupported: Bool? = nil) -> AuthorizationServerMetadata {
		AuthorizationServerMetadata(
			issuer: "https://issuer.example",
			authorizationEndpoint: "https://issuer.example/authorize",
			tokenEndpoint: tokenEndpoint.absoluteString,
			dpopSigningAlgValuesSupported: [JWSAlgorithm(.ES256)],
			authorizationResponseIssParameterSupported: issSupported
		)
	}

	private func resumeRequest(issSupported: Bool) throws -> AuthorizationRequested {
		try OpenId4VciService.makeResumeAuthorizationRequest(model: makePendingModel(), authorizePresentationUrl: Self.authorizeUrl, nonce: nil, authorizationServerMetadata: .oauth(Self.authorizationServerMetadata(issSupported: issSupported)))
	}

	private func authorize(request: AuthorizationRequested, networking: TokenEndpointStub, iss: String? = nil, issChecking: AuthorizationResponseIssChecking = .never) async throws -> AuthorizedRequest {
		let issuer = try await makeIssuer(networking: networking, issChecking: issChecking)
		return try await issuer.authorizeWithAuthorizationCode(
			serverState: Self.state,
			request: request,
			authorizationCode: try AuthorizationCode(value: "auth-code"),
			authorizationDetailsInTokenRequest: .doNotInclude,
			grant: .authorizationCode(try Grants.AuthorizationCode(authorizationServer: nil)),
			issuerFromRedirect: iss.flatMap(URL.init(string:))
		)
	}

	private func makeIssuer(networking: TokenEndpointStub, issChecking: AuthorizationResponseIssChecking) async throws -> Issuer {
		let metadataData = try #require(Data(name: "pid-demo-openid-credential-issuer", ext: "json", from: Bundle.module))
		let issuerMetadata = try JSONDecoder().decode(CredentialIssuerMetadata.self, from: metadataData)
		let authorizationServerMetadata = Self.authorizationServerMetadata()
		let vciConfig = try await OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example", clientId: "wallet", authResponseIssChecking: issChecking)
			.toOpenId4VCIConfig(credentialIssuerId: "https://issuer.example", clientAttestationPopSigningAlgValuesSupported: nil, context: ThreadSafeAuthContext())

		let privateKey = try #require(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256] as CFDictionary, nil))
		let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
		let dpopConstructor = DPoPConstructor(algorithm: JWSAlgorithm(.ES256), jwk: try ECPublicKey(publicKey: publicKey), privateKey: .secKey(privateKey))

		return try Issuer(
			authorizationServerMetadata: .oauth(authorizationServerMetadata),
			issuerMetadata: issuerMetadata,
			config: vciConfig,
			parPoster: Poster(session: networking),
			tokenPoster: Poster(session: networking),
			dpopConstructor: dpopConstructor
		)
	}

	private func makePendingModel() throws -> PendingIssuanceModel {
		PendingIssuanceModel(
			pendingReason: .presentation_request_url(Self.authorizeUrl),
			configuration: CredentialConfiguration(
				configurationIdentifier: try CredentialConfigurationIdentifier(value: "pid-sd-jwt"),
				credentialIssuerIdentifier: "https://issuer.example",
				vct: "urn:eudi:pid:de:1",
				supportsAttestationProofType: true,
				supportsJwtProofTypeWithAttestation: true,
				supportsPlainJwtProof: false,
				credentialSigningAlgValuesSupported: ["ES256"],
				dpopSigningAlgValuesSupported: ["ES256"],
				clientAttestationPopSigningAlgValuesSupported: nil,
				issuerDisplay: [],
				display: [],
				claims: [],
				format: .sdjwt,
				defaultCredentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1)
			),
			metadataKey: "https://issuer.example",
			pckeCodeVerifier: "code-verifier-0123456789012345678901234567890123",
			pckeCodeVerifierMethod: "S256",
			state: Self.state
		)
	}

	private func nonceClaim(of proof: String) throws -> String? {
		let segments = proof.split(separator: ".")
		try #require(segments.count == 3)
		var payload = String(segments[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
		payload += String(repeating: "=", count: (4 - payload.count % 4) % 4)
		let data = try #require(Data(base64Encoded: payload))
		let claims = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
		return claims["nonce"] as? String
	}
}

private actor TokenEndpointStub: Networking {
	enum Response {
		case success
		case useDpopNonce(String)
	}

	private var responses: [Response]
	private(set) var dpopProofs: [String] = []

	init(responses: [Response]) {
		self.responses = responses
	}

	func data(from url: URL) async throws -> (Data, URLResponse) {
		throw URLError(.unsupportedURL)
	}

	func data(for request: URLRequest) async throws -> (Data, URLResponse) {
		let url = try #require(request.url)
		if let proof = request.value(forHTTPHeaderField: "DPoP") {
			dpopProofs.append(proof)
		}
		switch responses.isEmpty ? .success : responses.removeFirst() {
		case .success:
			let body = #"{"access_token":"access-token","token_type":"DPoP","expires_in":3600,"refresh_token":"refresh-token"}"#
			return (Data(body.utf8), HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!)
		case .useDpopNonce(let nonce):
			let body = #"{"error":"use_dpop_nonce"}"#
			let headers = ["Content-Type": "application/json", "WWW-Authenticate": #"DPoP error="use_dpop_nonce""#, "DPoP-Nonce": nonce]
			return (Data(body.utf8), HTTPURLResponse(url: url, statusCode: 401, httpVersion: nil, headerFields: headers)!)
		}
	}
}
