import Testing
@testable import EudiWalletKit
import Foundation
import MdocDataModel18013
import OpenID4VCI
import SwiftyJSON
import WalletStorage

@Suite("Issuance response safety tests")
struct IssuanceResponseSafetyTests {
	@Test("Batch credential arrays use one global binding-key cursor")
	func batchCredentialPairing() throws {
		let credentials: [Credential] = [
			.json(JSON([["credential": "first"], ["credential": "second"]])),
			.json(JSON([["credential": "third"]]))
		]
		let keys = [Data([1]), Data([2]), Data([3])]

		let pairs = try OpenId4VciService.pairCredentialPayloads(
			credentials,
			format: .sdjwt,
			publicKeys: keys
		)

		#expect(pairs.map { $0.1 } == keys)
		#expect(pairs.compactMap { String(data: $0.0, encoding: .utf8) } == ["first", "second", "third"])
	}

	@Test("Negative issuance-result indexes fail safely")
	func negativeIssuanceIndex() throws {
		let authorized = AuthorizedRequest(
			accessToken: try IssuanceAccessToken(accessToken: "token", tokenType: .bearer),
			refreshToken: nil,
			credentialIdentifiers: nil,
			timeStamp: 0,
			dPopNonce: nil,
			grantType: nil
		)
		let outcome = IssuanceOutcome.issued(
			[(data: Data("credential".utf8), publicKey: Data([1]))],
			try makeCredentialConfiguration(),
			authorized,
			notificationId: nil
		)

		#expect(outcome.getDataToSave(index: -1, format: .sdjwt).isEmpty)
		#expect(outcome.getPublicKey(index: -1).isEmpty)
	}

	@Test("Credential and binding-key counts must match", arguments: [0, 2])
	func responseCardinalityMismatch(keyCount: Int) {
		let keys = (0..<keyCount).map { Data([UInt8($0)]) }
		#expect(throws: (any Error).self) {
			_ = try OpenId4VciService.pairCredentialPayloads(
				[.string("credential")],
				format: .sdjwt,
				publicKeys: keys
			)
		}
	}

	@Test("Invalid credential batch sizes are rejected", arguments: [0, -1, 101])
	func invalidBatchSize(batchSize: Int) {
		#expect(throws: (any Error).self) {
			try OpenId4VciService.validateBatchSize(batchSize)
		}
	}

	@Test("Pending issuance requires the original OAuth state", arguments: [nil, "attacker-state"])
	func pendingIssuanceStateMismatch(receivedState: String?) {
		#expect(throws: (any Error).self) {
			_ = try OpenId4VciService.validateAuthorizationState(
				receivedState,
				expectedState: "expected-state"
			)
		}
	}

	@Test("Pending issuance accepts its original OAuth state")
	func pendingIssuanceStateMatch() throws {
		let state = try OpenId4VciService.validateAuthorizationState(
			"expected-state",
			expectedState: "expected-state"
		)
		#expect(state == "expected-state")
	}

	@Test("Authorization-code callbacks take precedence over app URL schemes")
	func authorizationCallbackClassification() throws {
		let callback = try #require(URL(string: "wallet://authorize?code=abc&state=expected"))
		guard case .code(let code, let state) = try OpenId4VciService.classifyAuthenticationCallback(
			callback,
			applicationSchemes: ["wallet"]
		) else {
			Issue.record("Expected an authorization-code callback")
			return
		}
		#expect(code == "abc")
		#expect(state == "expected")

		let presentation = try #require(URL(string: "wallet://presentation/request"))
		guard case .presentation_request = try OpenId4VciService.classifyAuthenticationCallback(
			presentation,
			applicationSchemes: ["wallet"]
		) else {
			Issue.record("Expected a presentation callback")
			return
		}

		#expect(throws: WalletError.self) {
			_ = try OpenId4VciService.classifyAuthenticationCallback(
				try #require(URL(string: "attacker://presentation/request")),
				applicationSchemes: ["wallet"]
			)
		}
	}

	@Test("Concurrent issuance resumes are rejected")
	func concurrentResumeGuard() async throws {
		let storageService = TestDataStorageService()
		let storage = StorageManager(storageService: storageService)
		let service = try OpenId4VciService(
			uiCulture: nil,
			config: OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example"),
			networking: TestNetworking(metadata: Data()),
			storage: storage,
			storageService: storageService
		)
		let secondService = try OpenId4VciService(
			uiCulture: nil,
			config: OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example"),
			networking: TestNetworking(metadata: Data()),
			storage: storage,
			storageService: storageService
		)

		try await service.beginIssuanceResume(id: "pending", status: .pending)
		await #expect(throws: (any Error).self) {
			try await secondService.beginIssuanceResume(id: "pending", status: .deferred)
		}
		await service.endIssuanceResume(id: "pending", status: .pending)
		try await service.beginIssuanceResume(id: "pending", status: .pending)
		await service.endIssuanceResume(id: "pending", status: .pending)
	}

	@Test("Pending issuance persists a restart-safe offer request")
	func pendingOfferRequestRoundTrip() throws {
		let requestJSON = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]}"#
		let model = PendingIssuanceModel(
			pendingReason: .presentation_request_url("https://verifier.example/request"),
			configuration: try makeCredentialConfiguration(),
			metadataKey: "cache-key",
			offerRequestJSON: requestJSON,
			pckeCodeVerifier: "verifier",
			pckeCodeVerifierMethod: "S256",
			state: "state"
		)

		let encoded = try JSONEncoder().encode(model)
		let decoded = try JSONDecoder().decode(PendingIssuanceModel.self, from: encoded)
		#expect(decoded.offerRequestJSON == requestJSON)

		var legacyObject = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
		legacyObject.removeValue(forKey: "offerRequestJSON")
		let legacyData = try JSONSerialization.data(withJSONObject: legacyObject)
		let legacy = try JSONDecoder().decode(PendingIssuanceModel.self, from: legacyData)
		#expect(legacy.offerRequestJSON == nil)
	}

	private func makeCredentialConfiguration() throws -> CredentialConfiguration {
		CredentialConfiguration(
			configurationIdentifier: try CredentialConfigurationIdentifier(value: "pid"),
			credentialIssuerIdentifier: "https://issuer.example",
			vct: "urn:example:pid",
			supportsAttestationProofType: false,
			supportsJwtProofTypeWithAttestation: false,
			supportsJwtProofTypeWithoutAttestation: true,
			credentialSigningAlgValuesSupported: ["ES256"],
			dpopSigningAlgValuesSupported: nil,
			clientAttestationPopSigningAlgValuesSupported: nil,
			issuerDisplay: [],
			display: [],
			claims: [],
			format: .sdjwt,
			defaultCredentialOptions: CredentialOptions(credentialPolicy: .rotateUse, batchSize: 1)
		)
	}
}
