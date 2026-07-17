import Testing
@testable import EudiWalletKit
import Foundation
import MdocDataModel18013
import OpenID4VP
import StatiumSwift
import SwiftyJSON

@Suite("Extension safety tests")
struct ExtensionsSafetyTests {
	@Test("Negative JSON numbers remain signed and do not trap")
	func negativeJSONNumber() throws {
		let json = JSON(-1)
		let value = try #require(json.getDataValue(name: "signed", valueType: nil))
		#expect(value.0 == .double(-1))
		#expect(value.1 == "-1")
	}

	@Test("Fractional JSON numbers remain fractional")
	func fractionalJSONNumber() throws {
		let json = JSON(1.5)
		let value = try #require(json.getDataValue(name: "fraction", valueType: nil))
		#expect(value.0 == .double(1.5))
		#expect(value.1 == "1.5")
	}

	@Test("Standard P-521 JWK curve name is accepted")
	func standardP521CurveName() {
		#expect(CoseEcCurve(crvName: "P-521") == .P521)
		#expect(CoseEcCurve(crvName: "P-512") == .P521)
	}

	@Test("Status checks reject insecure status-list URLs before fetching")
	func statusCheckRequiresSecureURL() async {
		let service = DocumentStatusService(
			statusIdentifier: StatusIdentifier(idx: 0, uriString: "http://status.example/list"),
			verifier: AcceptingStatusVerifier()
		)
		do {
			_ = try await service.getStatus()
			Issue.record("Expected the status check to reject cleartext transport")
		} catch {
			#expect(error.localizedDescription.contains("HTTPS"))
		}
	}

	@Test("Status-list fetches use injected networking and a bounded response")
	func statusNetworkingIsInjectedAndBounded() async throws {
		let networking = StatusTestNetworking(
			statusCode: 200,
			responseURL: try #require(URL(string: "https://status.example/final")),
			data: Data("status-list".utf8)
		)
		let adapter = StatusNetworkingAdapter(networking: networking)
		let result = await adapter.get(
			url: try #require(URL(string: "https://status.example/list")),
			headers: ["Accept": "application/statuslist+jwt"]
		)

		guard case .success(let data) = result else {
			Issue.record("Expected injected status-list request to succeed")
			return
		}
		#expect(data == Data("status-list".utf8))
		#expect(await networking.maximumResponseBytes == 16 * 1_024 * 1_024)
		#expect(await networking.acceptHeader == "application/statuslist+jwt")
	}

	@Test("Status-list fetches reject insecure final response URLs")
	func statusNetworkingRejectsInsecureRedirect() async throws {
		let networking = StatusTestNetworking(
			statusCode: 200,
			responseURL: try #require(URL(string: "http://status.example/final")),
			data: Data()
		)
		let result = await StatusNetworkingAdapter(networking: networking).get(
			url: try #require(URL(string: "https://status.example/list")),
			headers: [:]
		)
		guard case .failure = result else {
			Issue.record("Expected an insecure final status-list URL to fail")
			return
		}
	}

	@Test("Invalid preregistered verifier URL is rejected")
	func invalidPreregisteredVerifierURL() {
		let client = PreregisteredClient(
			validatingClientId: "client",
			verifierApiUri: "not a URL",
			verifierLegalName: "Verifier"
		)
		#expect(client == nil)

		let legacyClient = PreregisteredClient(
			clientId: "client",
			verifierApiUri: "not a URL",
			verifierLegalName: "Verifier"
		)
		guard case .passByValue(let keySet) = legacyClient.jwkSetSource else {
			Issue.record("Invalid legacy endpoints must not produce a fetch URL")
			return
		}
		#expect(keySet.keys.isEmpty)
		#expect(PreregisteredClient(
			validatingClientId: "client",
			verifierApiUri: "http://verifier.example",
			verifierLegalName: "Verifier"
		) == nil)
	}

	@Test("Remote protocol URLs reject cleartext and local-network targets")
	func remoteURLValidation() throws {
		try EudiWallet.validateHTTPSRemoteURL(
			#require(URL(string: "https://issuer.example/offer?id=1")),
			purpose: "Test URL"
		)
		for value in [
			"http://issuer.example/offer",
			"file:///tmp/offer.json",
			"https://user:secret@issuer.example/offer",
			"https://issuer.example/offer#fragment",
			"https://localhost/offer",
			"https://127.0.0.1/offer",
			"https://192.168.1.10/offer",
			"https://[::1]/offer",
			"https://[fc00::1]/offer",
			"https://[fe90::1]/offer",
			"https://[::ffff:127.0.0.1]/offer",
			"https://0.0.0.0/offer",
			"https://2130706433/offer",
			"https://0177.0.0.1/offer",
			"https://0x7f000001/offer",
			"https://127.1/offer"
		] {
			let url = try #require(URL(string: value))
			#expect(throws: WalletError.self) {
				try EudiWallet.validateHTTPSRemoteURL(url, purpose: "Test URL")
			}
		}
	}

	@Test("Malformed transaction-log arrays do not trap")
	func malformedTransactionLogArrays() throws {
		let payload = VpResponsePayload(
			verifiable_presentations: [],
			data_formats: [.sdjwt],
			transaction_data: nil
		)
		let log = TransactionLog(
			timestamp: 0,
			status: .completed,
			rawResponse: try JSONEncoder().encode(payload),
			type: .presentation,
			dataFormat: .json,
			docMetadata: []
		)
		#expect(TransactionLogUtils.parseDocClaimsDecodables(log, uiCulture: nil).isEmpty)
	}

	@Test("Transaction metadata excludes persisted OAuth authorization data")
	func transactionMetadataRedaction() {
		let metadata = DocMetadata(
			credentialIssuerIdentifier: "https://issuer.example",
			configurationIdentifier: "pid",
			docType: "pid",
			display: nil,
			issuerDisplay: nil,
			claims: nil,
			authorizedRequestData: Data("access-token refresh-token".utf8),
			keyOptions: nil,
			credentialOptions: nil
		)
		#expect(metadata.redactedForTransactionLog().authorizedRequestData == nil)
	}

	@Test("Credential display images use injected HTTPS fetches")
	func injectedDisplayImageFetch() async throws {
		let metadata = DisplayMetadata(backgroundImageURL: "https://issuer.example/background.png")
		let downloaded = await metadata.downloadingImages { request in
			let response = try #require(HTTPURLResponse(
				url: request.url!,
				statusCode: 200,
				httpVersion: nil,
				headerFields: ["Content-Type": "image/png"]
			))
			return (Data([0x89, 0x50, 0x4e, 0x47]), response)
		}
		#expect(downloaded.backgroundImageURL?.hasPrefix("data:image/png;base64,") == true)
	}

	@Test("Insecure credential display image URLs are not fetched")
	func rejectsInsecureDisplayImageURL() async {
		let metadata = DisplayMetadata(backgroundImageURL: "http://issuer.example/background.png")
		let downloaded = await metadata.downloadingImages { _ in
			Issue.record("HTTP display image must not be fetched")
			throw CancellationError()
		}
		#expect(downloaded.backgroundImageURL == metadata.backgroundImageURL)
	}

	@Test("Log file APIs reject path traversal")
	func logFilePathTraversal() throws {
		for invalidName in ["../outside.log", "nested/wallet.log", "..", "/tmp/wallet.log", "nested\\wallet.log"] {
			#expect(throws: WalletError.self) {
				_ = try EudiWallet.getLogFileURL(invalidName)
			}
		}
		let validURL = try #require(try EudiWallet.getLogFileURL("wallet.log"))
		#expect(validURL.lastPathComponent == "wallet.log")
	}
}

private actor StatusTestNetworking: BoundedNetworkingProtocol {
	private let statusCode: Int
	private let responseURL: URL
	private let responseData: Data
	private(set) var maximumResponseBytes: Int?
	private(set) var acceptHeader: String?

	init(statusCode: Int, responseURL: URL, data: Data) {
		self.statusCode = statusCode
		self.responseURL = responseURL
		self.responseData = data
	}

	func data(from url: URL) async throws -> (Data, URLResponse) {
		try await data(for: URLRequest(url: url))
	}

	func data(for request: URLRequest) async throws -> (Data, URLResponse) {
		acceptHeader = request.value(forHTTPHeaderField: "Accept")
		let response = try #require(HTTPURLResponse(
			url: responseURL,
			statusCode: statusCode,
			httpVersion: nil,
			headerFields: nil
		))
		return (responseData, response)
	}

	func data(for request: URLRequest, maximumResponseBytes: Int) async throws -> (Data, URLResponse) {
		self.maximumResponseBytes = maximumResponseBytes
		return try await data(for: request)
	}
}

private struct AcceptingStatusVerifier: VerifyStatusListTokenSignature {
	func verify(statusListToken: Data, format: StatusListTokenFormat, at: Date) throws {}
}
