/*
Copyright (c) 2026 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import Foundation
import MdocDataModel18013
import OpenID4VCI
import Testing
import WalletStorage
@testable import EudiWalletKit

struct WalletVCIServiceIsolationTests {
	@Test("Wallets keep services with the same registered name isolated")
	func sameNameDoesNotReplaceAnotherWalletService() async throws {
		let firstIssuer = "https://first-issuer.example"
		let secondIssuer = "https://second-issuer.example"
		let firstWallet = try makeWallet(
			issuerName: "issuer",
			configuration: OpenId4VciConfiguration(credentialIssuerURL: firstIssuer)
		)
		let secondWallet = try makeWallet(
			issuerName: "issuer",
			configuration: OpenId4VciConfiguration(credentialIssuerURL: secondIssuer)
		)

		let firstService = try await firstWallet.resolveVCIService(issuerName: "issuer")
		let secondService = try await secondWallet.resolveVCIService(issuerName: "issuer")
		let firstConfiguration = await firstService.config
		let secondConfiguration = await secondService.config

		#expect(ObjectIdentifier(firstService) != ObjectIdentifier(secondService))
		#expect(firstConfiguration.credentialIssuerURL == firstIssuer)
		#expect(secondConfiguration.credentialIssuerURL == secondIssuer)
	}

	@Test("Issuer URL lookup cannot resolve a service owned by another wallet")
	func issuerURLLookupIsWalletScoped() async throws {
		let issuerURL = "https://private-issuer.example"
		let owningWallet = try makeWallet(
			issuerName: "private",
			configuration: OpenId4VciConfiguration(credentialIssuerURL: issuerURL)
		)
		let unrelatedWallet = try makeWallet()

		await #expect(throws: (any Error).self) {
			_ = try await unrelatedWallet.resolveVCIService(issuerName: issuerURL)
		}
		_ = try await owningWallet.resolveVCIService(issuerName: issuerURL)
	}

	@Test("One wallet rejects ambiguous duplicate issuer registrations")
	func duplicateIssuerURLIsRejected() {
		let issuerURL = "https://issuer.example/path"
		#expect(throws: WalletError.self) {
			_ = try EudiWallet(
				eudiWalletConfig: EudiWalletConfiguration(serviceName: uniqueServiceName()),
				storageService: IsolationStorageService(),
				openID4VciConfigurations: [
					"first": OpenId4VciConfiguration(credentialIssuerURL: issuerURL),
					"second": OpenId4VciConfiguration(credentialIssuerURL: issuerURL + "/")
				]
			)
		}
	}

	@Test("Unknown issuers receive a minimal configuration")
	func autoRegistrationDoesNotInheritAnotherIssuerConfiguration() async throws {
		let trustedRedirect = URL(string: "trusted-wallet://authorize")!
		let requestedRedirect = URL(string: "one-off-wallet://authorize")!
		let trustedConfiguration = OpenId4VciConfiguration(
			credentialIssuerURL: "https://trusted-issuer.example",
			clientId: "confidential-client-id",
			authFlowRedirectionURI: trustedRedirect,
			requireDpop: false,
			userAuthenticationRequired: true
		)
		let wallet = try makeWallet(
			issuerName: "trusted",
			configuration: trustedConfiguration
		)

		let unknownService = try await wallet.autoRegisterVciConfiguration(
			"https://unknown-issuer.example",
			requestedRedirect
		)
		let unknownConfiguration = await unknownService.config

		#expect(unknownConfiguration.credentialIssuerURL == "https://unknown-issuer.example")
		#expect(unknownConfiguration.authFlowRedirectionURI == requestedRedirect)
		#expect(unknownConfiguration.clientId == "eudiw-abca")
		#expect(unknownConfiguration.requireDpop)
		#expect(!unknownConfiguration.userAuthenticationRequired)
	}

	@Test("One-off configuration creates an ephemeral service")
	func oneOffConfigurationDoesNotMutateRegisteredService() async throws {
		let issuerURL = "https://issuer.example"
		let registeredConfiguration = OpenId4VciConfiguration(
			credentialIssuerURL: issuerURL,
			clientId: "registered-client"
		)
		let wallet = try makeWallet(
			issuerName: "issuer",
			configuration: registeredConfiguration
		)
		let registeredService = try await wallet.resolveVCIService(issuerName: "issuer")
		let override = OpenId4VciConfiguration(
			credentialIssuerURL: "https://caller-supplied-but-not-authoritative.example",
			clientId: "one-off-client"
		)

		let ephemeralService = try wallet.makeEphemeralOpenId4VciService(
			issuerURL: issuerURL,
			configuration: override
		)
		let resolvedAgain = try await wallet.resolveVCIService(issuerName: "issuer")
		let ephemeralConfiguration = await ephemeralService.config
		let registeredConfigurationAfterOverride = await resolvedAgain.config

		#expect(ObjectIdentifier(ephemeralService) != ObjectIdentifier(registeredService))
		#expect(ObjectIdentifier(resolvedAgain) == ObjectIdentifier(registeredService))
		#expect(ephemeralConfiguration.credentialIssuerURL == issuerURL)
		#expect(ephemeralConfiguration.clientId == "one-off-client")
		#expect(registeredConfigurationAfterOverride.clientId == "registered-client")
	}

	@Test("Changing the wallet transaction logger updates registered services")
	func changingTransactionLoggerPropagatesToServices() async throws {
		let wallet = try makeWallet(
			issuerName: "issuer",
			configuration: OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example")
		)
		let service = try await wallet.resolveVCIService(issuerName: "issuer")
		let replacementLogger = IsolationTransactionLogger()

		wallet.transactionLogger = replacementLogger
		// Resolving is also a synchronization point for callers that immediately
		// use a service after changing the logger.
		_ = try await wallet.resolveVCIService(issuerName: "issuer")
		let serviceLogger = await service.transactionLogger

		#expect(serviceLogger.map { ObjectIdentifier($0 as AnyObject) } == ObjectIdentifier(replacementLogger))
	}

	@Test("Compatibility metadata lookup works before published collections are loaded")
	func coldStartCompatibilityLookupChecksPersistedStatuses() async throws {
		let documentId = "pending-document"
		let metadata = DocMetadata(
			credentialIssuerIdentifier: "https://issuer.example",
			configurationIdentifier: "pid",
			docType: "eu.europa.ec.eudi.pid.1",
			display: nil,
			issuerDisplay: nil,
			claims: nil,
			authorizedRequestData: nil,
			keyOptions: nil,
			credentialOptions: nil
		)
		let storage = IsolationStorageService(metadata: [
			.pending: [documentId: metadata]
		])
		let wallet = try EudiWallet(
			eudiWalletConfig: EudiWalletConfiguration(serviceName: uniqueServiceName()),
			storageService: storage
		)

		let authorizedRequest = try await wallet.storedAuthorizedRequestParams(docId: documentId)
		let requestedStatuses = await storage.requestedStatuses

		#expect(authorizedRequest == nil)
		#expect(requestedStatuses == [.issued, .deferred, .pending])
	}

	@Test("By-reference offers select the registered issuer policy before metadata fetch")
	func byReferenceOfferUsesRegisteredStrictPolicy() async throws {
		let issuerURL = "https://strict-issuer.example"
		let networking = RecordingOfferNetworking(issuerURL: issuerURL)
		let policy = IssuerMetadataPolicy.requireSigned(
			issuerTrust: .byCertificateChain(certificateChainTrust: AcceptAllCertificateTrust())
		)
		let wallet = try EudiWallet(
			eudiWalletConfig: EudiWalletConfiguration(serviceName: uniqueServiceName()),
			storageService: IsolationStorageService(),
			openID4VciConfigurations: [
				"strict": OpenId4VciConfiguration(
					credentialIssuerURL: issuerURL,
					issuerMetadataPolicy: policy
				)
			],
			networking: networking
		)

		await #expect(throws: (any Error).self) {
			_ = try await wallet.resolveCredentialOffer(offerUri: "https://offers.example/offer")
		}
		#expect(networking.lastAcceptHeader == "application/jwt")
	}

	private func makeWallet(
		issuerName: String? = nil,
		configuration: OpenId4VciConfiguration? = nil
	) throws -> EudiWallet {
		let configurations: [String: OpenId4VciConfiguration]? = if let issuerName, let configuration {
			[issuerName: configuration]
		} else {
			nil
		}
		return try EudiWallet(
			eudiWalletConfig: EudiWalletConfiguration(serviceName: uniqueServiceName()),
			storageService: IsolationStorageService(),
			openID4VciConfigurations: configurations
		)
	}

	private func uniqueServiceName() -> String {
		"wallet-vci-isolation-\(UUID().uuidString)"
	}
}

private struct AcceptAllCertificateTrust: CertificateChainTrust {
	func isValid(chain: [String]) -> Bool { true }
}

private final class RecordingOfferNetworking: @unchecked Sendable, BoundedNetworkingProtocol {
	private let issuerURL: String
	private let lock = NSLock()
	private var acceptHeader: String?

	init(issuerURL: String) {
		self.issuerURL = issuerURL
	}

	var lastAcceptHeader: String? {
		lock.withLock { acceptHeader }
	}

	func data(from url: URL) async throws -> (Data, URLResponse) {
		let object: [String: Any] = [
			"credential_issuer": issuerURL,
			"credential_configuration_ids": ["pid"]
		]
		let data = try JSONSerialization.data(withJSONObject: object)
		return (data, response(url: url, contentType: "application/json"))
	}

	func data(for request: URLRequest) async throws -> (Data, URLResponse) {
		lock.withLock { acceptHeader = request.value(forHTTPHeaderField: "Accept") }
		if request.url?.host == "offers.example" {
			let object: [String: Any] = [
				"credential_issuer": issuerURL,
				"credential_configuration_ids": ["pid"]
			]
			let data = try JSONSerialization.data(withJSONObject: object)
			return (data, response(url: request.url!, contentType: "application/json"))
		}
		return (Data("{}".utf8), response(url: request.url!, contentType: "application/json"))
	}

	func data(for request: URLRequest, maximumResponseBytes: Int) async throws -> (Data, URLResponse) {
		let result = try await data(for: request)
		guard maximumResponseBytes >= 0, result.0.count <= maximumResponseBytes else {
			throw WalletError(description: "Network response exceeds the configured size limit")
		}
		return result
	}

	private func response(url: URL, contentType: String) -> HTTPURLResponse {
		HTTPURLResponse(
			url: url,
			statusCode: 200,
			httpVersion: nil,
			headerFields: ["Content-Type": contentType]
		)!
	}
}

private actor IsolationStorageService: DataStorageService {
	private let metadata: [DocumentStatus: [String: DocMetadata]]
	private(set) var requestedStatuses: [DocumentStatus] = []

	init(metadata: [DocumentStatus: [String: DocMetadata]] = [:]) {
		self.metadata = metadata
	}

	func loadDocument(id: String, status: DocumentStatus) async throws -> WalletStorage.Document? { nil }

	func loadDocumentMetadata(id: String, status: DocumentStatus) async throws -> DocMetadata? {
		requestedStatuses.append(status)
		return metadata[status]?[id]
	}

	func loadDocuments(status: DocumentStatus) async throws -> [WalletStorage.Document]? { [] }
	func saveDocument(_ document: WalletStorage.Document, batch: [WalletStorage.Document]?, allowOverwrite: Bool) async throws {}
	func deleteDocument(id: String, status: DocumentStatus) async throws {}
	func deleteDocuments(status: DocumentStatus) async throws {}
	func deleteDocumentCredential(id: String, index: Int) async throws {}
}

private actor IsolationTransactionLogger: TransactionLogger {
	func log(transaction: TransactionLog) async throws {}
}
