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
import MdocSecurity18013
import MdocDataTransfer18013
import WalletStorage
import LocalAuthentication
import CryptoKit
import StatiumSwift
import SwiftCBOR
#if canImport(Darwin)
import Darwin
#endif
// ios specific imports
#if canImport(UIKit)
import UIKit
#endif
import protocol OpenID4VCI.Networking
import OpenID4VCI
import eudi_lib_sdjwt_swift

/// User wallet implementation
public final class EudiWallet: ObservableObject, @unchecked Sendable {
	/// Storage manager instance
	public private(set) var storage: StorageManager!
	/// Wallet configuration
	public var eudiWalletConfig: EudiWalletConfiguration
	/// OpenID4VP configuration
	public var openID4VpConfig: OpenId4VpConfiguration
	/// transaction logger
	/// Transaction logger used by subsequent wallet operations.
	/// Registered services receive the current value synchronously when resolved,
	/// avoiding unordered background propagation when this property changes rapidly.
	public var transactionLogger: (any TransactionLogger)?
	/// OpenID4VCI issuer parameters
	public private(set) var openID4VciConfigurations: [String: OpenId4VciConfiguration]?
	/// Wallet-scoped registry for services that retain this wallet's dependencies.
	let openId4VciServiceRegistry = WalletOpenId4VciServiceRegistry()
	/// Wallet-scoped credential-offer cache shared by this wallet's issuer services.
	let openId4VciCache = OpenId4VciCache()
	/// Can be used to set a custom networking client for network requests during OpenID4VCI operations.
	let networkingVci: OpenID4VCINetworking
	/// Can be used to set a custom networking client for network requests during OpenID4VP operations.
	let networkingVp: OpenID4VPNetworking
	/// Optional model factory type to create custom stronly-typed models
	public private(set) var modelFactory: (any DocClaimsDecodableFactory)?
	/// Ble transfer mode
	public var bleTransferMode: BleTransferMode = .server
	/// Repository for zk system parameters, used in mdoc presentation when zk proofs are required.
	public var zkSystemRepository: ZkSystemRepository?

	/// Initialize a wallet instance using a configuration object.
	/// - Parameters:
	///   - eudiWalletConfig: Wallet configuration containing user preferences and settings.
	///   - storageService: The storage service to use for documents. Defaults to KeyChainStorageService.
	///   - openID4VpConfig: OpenID4VP configuration. Optional.
	///   - openID4VciConfigurations: A dictionary of OpenId4VciConfiguration objects keyed by an arbitrary issuer name. Optional.
	///   - networking: The networking Client to use for network requests. Optional.
	///   - secureAreas: An array of secure areas. Optional.
	///   - transactionLogger: Transaction logger for logging wallet operations. Optional.
	///   - modelFactory: The factory for creating Mdoc models. Optional.
	///   - zkSystemRepository: Repository for zk system parameters. Optional.
	///
	/// - Throws: An error if initialization fails.
	///
	/// ```swift
	/// let config = EudiWalletConfiguration(trustedReaderCertificates: [Data(name: "eudi_pid_issuer_ut", ext: "der")!])
	/// let wallet = try! EudiWallet(eudiWalletConfig: config)
	/// ```
	public init(
		eudiWalletConfig: EudiWalletConfiguration,
		storageService: (any DataStorageService)? = nil,
		openID4VpConfig: OpenId4VpConfiguration? = nil,
		openID4VciConfigurations: [String: OpenId4VciConfiguration]? = nil,
		networking: (any NetworkingProtocol)? = nil,
		secureAreas: [any SecureArea]? = nil,
		transactionLogger: (any TransactionLogger)? = nil,
		modelFactory: (any DocClaimsDecodableFactory)? = nil,
		zkSystemRepository: ZkSystemRepository? = nil
	) throws {
		try Self.validateServiceParams(serviceName: eudiWalletConfig.serviceName)
		self.eudiWalletConfig = eudiWalletConfig
		self.openID4VpConfig = openID4VpConfig ?? OpenId4VpConfiguration()
		self.transactionLogger = transactionLogger
		self.openID4VciConfigurations = openID4VciConfigurations
		let suppliedNetworking: any NetworkingProtocol
		if let networking { suppliedNetworking = networking }
		else { suppliedNetworking = URLSession.shared }
		guard let boundedNetworking = suppliedNetworking as? any BoundedNetworkingProtocol else {
			throw WalletError(description: "Custom networking must conform to BoundedNetworkingProtocol")
		}
		self.networkingVci = OpenID4VCINetworking(networking: boundedNetworking)
		self.networkingVp = OpenID4VPNetworking(networking: boundedNetworking)
		let storageServiceObj = storageService ?? KeyChainStorageService(serviceName: self.eudiWalletConfig.serviceName, accessGroup: self.eudiWalletConfig.accessGroup)
		self.modelFactory = modelFactory
		self.zkSystemRepository = zkSystemRepository
		self.bleTransferMode = eudiWalletConfig.bleTransferMode
		storage = StorageManager(storageService: storageServiceObj, modelFactory: modelFactory)
		if let secureAreas, !secureAreas.isEmpty {
			for asa in secureAreas { SecureAreaRegistry.shared.register(secureArea: asa) }
		} else {
			// register default secure areas
			let kcSks = KeyChainSecureKeyStorage(serviceName: self.eudiWalletConfig.serviceName, accessGroup: eudiWalletConfig.accessGroup)
			if SecureEnclave.isAvailable { SecureAreaRegistry.shared.register(secureArea: SecureEnclaveSecureArea.create(storage: kcSks)) }
			SecureAreaRegistry.shared.register(secureArea: SoftwareSecureArea.create(storage: kcSks))
		}
		if let openID4VciConfigurations { try registerOpenId4VciServices(openID4VciConfigurations) }
		if let logFileName = eudiWalletConfig.legacyLogFileName {
			_ = try Self.getLogFileURL(logFileName)
		}
	}

	/// Helper method to return a file URL from a file name.
	///
	/// The file is created in the caches directory
	/// - Parameter fileName: A file name
	/// - Returns: Th URL of a log file stored in the caches directory
	nonisolated public static func getLogFileURL(_ fileName: String) throws -> URL? {
		guard !fileName.isEmpty,
			fileName != ".",
			fileName != "..",
			fileName == URL(fileURLWithPath: fileName).lastPathComponent,
			!fileName.contains("/"),
			!fileName.contains("\\") else {
			throw WalletError(description: "Log file name must be a single file name")
		}
		let caches = try FileManager.getCachesDirectory().standardizedFileURL.resolvingSymlinksInPath()
		let candidate = caches.appendingPathComponent(fileName, isDirectory: false).standardizedFileURL
		let resolvedCandidate = candidate.resolvingSymlinksInPath()
		guard resolvedCandidate.deletingLastPathComponent() == caches else {
			throw WalletError(description: "Log file must remain inside the caches directory")
		}
		return candidate
	}

	private static func validateServiceParams(serviceName: String? = nil) throws {
		guard (serviceName?.contains(":") ?? false) == false else {
			let msg = "Not allowed service name, contains : character"
			logger.error("validateServiceParams:\(msg)")
			throw WalletError(description: msg)
		}
	}

	/// Get the contents of a log file stored in the caches directory
	/// - Parameter fileName: A file name
	/// - Returns: The file contents
	public func getLogFileContents(_ fileName: String) throws -> String {
		let logFileURL = try Self.getLogFileURL(fileName)
		guard let logFileURL else { throw WalletError(description: "Cannot create URL for file name \(fileName)") }
		return try String(contentsOf: logFileURL, encoding: .utf8)
	}

	/// Reset a log file stored in the caches directory
	/// - Parameter fileName: A file name
	public func resetLogFile(_ fileName: String) throws {
		let logFileURL = try Self.getLogFileURL(fileName)
		guard let logFileURL else { throw WalletError(description: "Cannot create URL for file name \(fileName)") }
		try FileManager.default.removeItem(at: logFileURL)
	}

	/// Register OpenID4VCI services for each configuration.
	/// - Parameter configurations: A dictionary of OpenId4VciConfiguration objects keyed by an arbitrary issuer name
	public func registerOpenId4VciServices(_ configurations: [String: OpenId4VciConfiguration]) throws {
		for (name, config) in configurations {
			try registerOpenId4VciService(name: name, config: config)
		}
	}
	/// Resolve a VCI service by name or issuer URL.
	/// - Parameter issuerName: The registered name or issuer URL of the service
	/// - Returns: The resolved `OpenId4VCIService`
	/// - Throws: If no service is registered for the given name or URL
	func resolveVCIService(issuerName: String) async throws -> OpenId4VciService {
		var vciService = openId4VciServiceRegistry.get(name: issuerName)
		if vciService == nil { vciService = openId4VciServiceRegistry.getByIssuerURL(issuerName) }
		guard let vciService else {
			throw PresentationSession.makeError(str: "No OpenId4VCI service registered for name \(issuerName)")
		}
		await vciService.setWalletTransactionLogger(transactionLogger)
		return vciService
	}

	static func validateHTTPSRemoteURL(_ url: URL, purpose: String) throws {
		guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
			components.scheme?.lowercased() == "https",
			let host = components.host?.lowercased(),
			!host.isEmpty,
			components.user == nil,
			components.password == nil,
			components.fragment == nil,
			!Self.isLocalNetworkHost(host) else {
			throw WalletError(description: "\(purpose) must use an HTTPS URL without credentials, fragments, or a local-network host")
		}
	}

	private static func isLocalNetworkHost(_ host: String) -> Bool {
		let host = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
		if host == "localhost" || host.hasSuffix(".localhost") || host.hasSuffix(".local") {
			return true
		}
		#if canImport(Darwin)
		var ipv4 = in_addr()
		if inet_aton(host, &ipv4) == 1 {
			return isNonPublicIPv4(UInt32(bigEndian: ipv4.s_addr))
		}
		var ipv6 = in6_addr()
		if inet_pton(AF_INET6, host, &ipv6) == 1 {
			let bytes = withUnsafeBytes(of: &ipv6) { Array($0.prefix(16)) }
			let isUnspecified = bytes.allSatisfy { $0 == 0 }
			let isLoopback = bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
			let isUniqueLocal = (bytes[0] & 0xfe) == 0xfc
			let isLinkLocal = bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
			let isMulticast = bytes[0] == 0xff
			let isIPv4Mapped = bytes.prefix(10).allSatisfy { $0 == 0 } && bytes[10] == 0xff && bytes[11] == 0xff
			if isIPv4Mapped {
				let embedded = (UInt32(bytes[12]) << 24) | (UInt32(bytes[13]) << 16) | (UInt32(bytes[14]) << 8) | UInt32(bytes[15])
				return isNonPublicIPv4(embedded)
			}
			return isUnspecified || isLoopback || isUniqueLocal || isLinkLocal || isMulticast
		}
		#endif
		return false
	}

	private static func isNonPublicIPv4(_ address: UInt32) -> Bool {
		let first = UInt8((address >> 24) & 0xff)
		let second = UInt8((address >> 16) & 0xff)
		return first == 0
			|| first == 10
			|| first == 127
			|| (first == 100 && (64...127).contains(second))
			|| (first == 169 && second == 254)
			|| (first == 172 && (16...31).contains(second))
			|| (first == 192 && (second == 0 || second == 168))
			|| (first == 198 && (second == 18 || second == 19))
			|| first >= 224
	}

	/// Create a service bound to this wallet without registering it.
	///
	/// This is used for one-off issuance configuration overrides so a single
	/// operation cannot mutate the policy used by later operations.
	func makeOpenId4VciService(config: OpenId4VciConfiguration) throws -> OpenId4VciService {
		try OpenId4VciService(
			uiCulture: eudiWalletConfig.uiCulture,
			config: config,
			networking: networkingVci,
			storage: storage,
			storageService: storage.storageService,
			transactionLogger: transactionLogger,
			cache: openId4VciCache
		)
	}

	func makeEphemeralOpenId4VciService(
		issuerURL: String,
		configuration: OpenId4VciConfiguration
	) throws -> OpenId4VciService {
		try makeOpenId4VciService(
			config: configuration.copy(credentialIssuerURL: issuerURL)
		)
	}

	/// Register an OpenId4VCI service with a given name and configuration.
	@discardableResult func registerOpenId4VciService(name: String, config: OpenId4VciConfiguration) throws -> OpenId4VciService {
		let vciService = try makeOpenId4VciService(config: config)
		try openId4VciServiceRegistry.register(name: name, issuerURL: config.credentialIssuerURL, service: vciService)
		// A registration can strengthen issuer policy. Never retain offers resolved
		// under the service it replaced.
		openId4VciCache.removeAllCredentialOffers()
		return vciService
	}

	/// Get issuer metadata using OpenId4VCI protocol
	/// - Parameter issuerName: The name of the issuer service
	/// - Returns: The issuer metadata
	public func getIssuerMetadata(issuerName: String) async throws -> CredentialIssuerMetadata {
		let vciService = try await resolveVCIService(issuerName: issuerName)
		return try await vciService.getIssuerMetadata()
	}

	/// Issue multiple documents using OpenId4Vci protocol
	///
	/// If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document"
	/// - Parameters:
	///   - issuerName: The name of the issuer service
	///   - docTypeIdentifiers: Array of document type identifiers (msoMdoc, sdJwt, or configuration identifier)
	///   - credentialOptions: Credential options specifying batch size and credential policy. If nil, defaults are fetched from issuer metadata.
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: Array of issued documents. They are saved in storage.
	@discardableResult public func issueDocuments(issuerName: String, docTypeIdentifiers: [DocTypeIdentifier], credentialOptions: CredentialOptions? = nil, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {
		let vciService = try await resolveVCIService(issuerName: issuerName)
		return try await vciService.issueDocuments(docTypeIdentifiers: docTypeIdentifiers, credentialOptions: credentialOptions, keyOptions: keyOptions, promptMessage: promptMessage)
	}

	/// Create a batch of keys and a matching key attestation using the attestation provider configured for the issuer.
	///
	/// - Parameters:
	///   - issuerName: The registered issuer service name or issuer URL.
	///   - id: The identifier used for the generated key batch.
	///   - credentialOptions: Credential options specifying the batch size and credential policy.
	///   - keyOptions: Key options controlling secure area and curve selection.
	///   - nonce: Optional nonce forwarded to the attestation provider.
	/// - Returns: A `BatchCreateKeyResult` containing the generated keys and the attestation JWT for that batch.
	public func createKeyBatchWithAttestation(issuerName: String, id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil, nonce: String? = nil) async throws -> BatchCreateKeyResult {
		let vciService = try await resolveVCIService(issuerName: issuerName)
		return try await vciService.createKeyBatchWithAttestation(id: id, credentialOptions: credentialOptions, keyOptions: keyOptions, nonce: nonce)
	}

	func getDocumentMetadata(documentId: WalletStorage.Document.ID) async throws -> DocMetadata {
		// The published collections may not have been loaded yet after launch.
		// Query each persisted status instead of guessing from in-memory state.
		for status in [DocumentStatus.issued, .deferred, .pending] {
			if let docMetadata = try await storage.storageService.loadDocumentMetadata(
				id: documentId,
				status: status
			) {
				return docMetadata
			}
		}
		throw PresentationSession.makeError(str: "Document metadata not found for id: \(documentId)", localizationKey: "doc_metadata_not_found", code: .credentialNotFound, context: ["documentId": documentId])
	}

	/// Returns stored credential options for a previously issued document.
	/// - Parameter documentId: The document identifier.
	/// - Returns: The credential options persisted in document metadata.
	/// - Throws: If document metadata is not found or does not include credential options.
	public func getDocumentCredentialOptions(documentId: WalletStorage.Document.ID) async throws -> CredentialOptions {
		let docMetadata = try await getDocumentMetadata(documentId: documentId)
		guard let credentialOptions = docMetadata.credentialOptions else {
			throw PresentationSession.makeError(str: "Credential options not found for document id: \(documentId)", code: .claimNotFound, context: ["documentId": documentId, "claim": "credentialOptions"])
		}
		return credentialOptions
	}

	/// Reissue an existing document using previously stored issuance metadata and authorization data.
	///
	/// This method retrieves the document's metadata from storage and uses its credential issuer identifier
	/// to resolve the appropriate OpenID4VCI service. If the document's metadata contains persisted authorization
	/// data, it is forwarded to the service to avoid re-authentication when possible.
	///
	/// - Parameters:
	///   - documentId: The unique identifier of the previously issued document to reissue.
	///   - credentialOptions: Credential options specifying batch size and credential policy. If nil, the options from the original issuance metadata are used.
	///   - keyOptions: Key options (secure area name and other options) for the document. If nil, the options from the original issuance metadata are used.
	///   - promptMessage: Prompt message for biometric authentication (optional).
	///   - backgroundOnly: When `true`, reissuance proceeds only if stored authorization data is available (no user interaction). Throws if authorization data is absent. Defaults to `false`.
	/// - Returns: The reissued document, saved in storage.
	/// - Throws: An error if the document metadata is not found, if `backgroundOnly` is `true` and no stored authorization data exists, or if reissuance fails.
	@discardableResult public func reissueDocument(
		documentId: WalletStorage.Document.ID,
		credentialOptions: CredentialOptions? = nil,
		keyOptions: KeyOptions? = nil,
		promptMessage: String? = nil,
		backgroundOnly: Bool = false
	) async throws -> WalletStorage.Document {
		let docMetadata = try await getDocumentMetadata(documentId: documentId)
		let vciService = try await resolveVCIService(issuerName: docMetadata.credentialIssuerIdentifier)
		let authorized: AuthorizedRequest? = docMetadata.authorizedRequestData
			.flatMap { try? JSONDecoder().decode(AuthorizedRequestData.self, from: $0) }
			.map { $0.toAuthorizedRequest() }
		if backgroundOnly && authorized == nil {
			throw PresentationSession.makeError(str: "Background reissuance not possible: no stored authorization data for document \(documentId)", localizationKey: "background_reissue_not_possible")
		}
		let resolvedCredentialOptions = credentialOptions ?? docMetadata.credentialOptions
		let resolvedKeyOptions = keyOptions ?? docMetadata.keyOptions
		let reissued = try await vciService.reissueDocument(documentId: documentId, docMetadata: docMetadata, authorized: authorized, credentialOptions: resolvedCredentialOptions, keyOptions: resolvedKeyOptions, promptMessage: promptMessage, backgroundOnly: backgroundOnly)
		guard let document = reissued.first else {
			throw PresentationSession.makeError(str: "Issuer returned no replacement credential")
		}
		return document
	}

	/// Get default credential options (batch-size and credential policy) for a document type
	///
	/// Queries the issuer's metadata to retrieve recommended credential configuration. The returned `CredentialOptions` contains:
	/// - `batchSize`: Number of credentials to issue in a batch (enables multiple presentations before re-issuance)
	/// - `credentialPolicy`: Either `.oneTimeUse` (credential consumed after presentation) or `.rotateUse` (unlimited presentations)
	/// - Parameters:
	///   - issuerName: The name of the issuer service
	///   - docTypeIdentifier: Document type identifier (msoMdoc, sdJwt, or configuration identifier)
	/// - Returns: Issuer-recommended credential options
	public func getDefaultCredentialOptions(issuerName: String, docTypeIdentifier: DocTypeIdentifier) async throws -> CredentialOptions {
		let vciService = try await resolveVCIService(issuerName: issuerName)
		return try await vciService.getMetadataDefaultCredentialOptions(docTypeIdentifier)
	}

	/// Request a deferred issuance based on a stored deferred document. On success, the deferred document is replaced with the issued document.
	///
	/// The caller does not need to reload documents, storage manager collections are updated.
	/// - Parameters:
	///   - issuerName: The name of the issuer service
	///   - deferredDoc: A stored document with deferred status
	///   - credentialOptions: Credential options specifying batch size and credential policy for the deferred document
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	/// - Returns: The issued document in case it was approved in the backend and the deferred data are valid, otherwise a deferred status document
	@discardableResult public func requestDeferredIssuance(issuerName: String, deferredDoc: WalletStorage.Document, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil) async throws -> WalletStorage.Document {
		let vciService = try await resolveVCIService(issuerName: issuerName)
		return try await vciService.requestDeferredIssuance(deferredDoc: deferredDoc, credentialOptions: credentialOptions, keyOptions: keyOptions)
	}

	/// Resume pending issuance. Supports dynamic issuance scenario
	///
	/// The caller does not need to reload documents, storage manager collections are updated.
	/// - Parameters:
	///   - issuerName: The name of the issuer service
	///   - pendingDoc: A temporary document with pending status
	///   - webUrl: The authorization URL returned from the presentation service (for dynamic issuance)
	///   - credentialOptions: Credential options specifying batch size and credential policy for the pending document
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	/// - Returns: The issued document in case it was approved in the backend and the pendingDoc data are valid, otherwise a pendingDoc status document
	@discardableResult public func resumePendingIssuance(issuerName: String, pendingDoc: WalletStorage.Document, webUrl: URL?, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil) async throws -> WalletStorage.Document {
		let vciService = try await resolveVCIService(issuerName: issuerName)
		return try await vciService.resumePendingIssuance(pendingDoc: pendingDoc, webUrl: webUrl, credentialOptions: credentialOptions, keyOptions: keyOptions)
	}

	// Get fallback service or create new config
	func autoRegisterVciConfiguration(_ urlString: String, _ authFlowRedirectionURI: URL?) async throws -> OpenId4VciService {
		logger.warning("Issuer for url \(urlString) not registered.")
		// An unknown issuer must not inherit client credentials, trust anchors,
		// attestation providers, or policy from an unrelated registered issuer.
		let config = OpenId4VciConfiguration(
			credentialIssuerURL: urlString,
			authFlowRedirectionURI: authFlowRedirectionURI
		)
		let vciService = try registerOpenId4VciService(name: urlString, config: config)
		return vciService
	}

	/// Resolve an offer in two stages so a by-reference offer's issuer is known
	/// before issuer metadata is fetched and its signature policy is selected.
	func resolveCredentialOffer(
		offerUri: String,
		policyOverride: IssuerMetadataPolicy? = nil
	) async throws -> CredentialOffer {
		let source = try CredentialOfferRequest(urlString: offerUri)
		let requestObject: CredentialOfferRequestObject
		switch source {
		case .passByValue(let value):
			guard let parsed = CredentialOfferRequestObject(jsonString: value) else {
				throw PresentationSession.makeError(str: "Unable to parse credential offer")
			}
			requestObject = parsed
		case .fetchByReference(let url):
			try Self.validateHTTPSRemoteURL(url, purpose: "Credential offer reference")
			let fetched = await Fetcher<CredentialOfferRequestObject>(session: networkingVci).fetch(url: url)
			do { requestObject = try fetched.get() }
			catch { throw PresentationSession.makeError(str: "Unable to fetch credential offer") }
		}
		guard let credentialIssuerURL = URL(string: requestObject.credentialIssuer) else {
			throw PresentationSession.makeError(str: "Credential offer contains an invalid issuer URL")
		}
		try Self.validateHTTPSRemoteURL(credentialIssuerURL, purpose: "Credential issuer")

		let registeredService = openId4VciServiceRegistry.getByIssuerURL(requestObject.credentialIssuer)
		let policy = policyOverride ?? registeredService?.config.issuerMetadataPolicy ?? .ignoreSigned
		let normalizedData = try JSONEncoder().encode(requestObject)
		guard let normalizedOffer = String(data: normalizedData, encoding: .utf8) else {
			throw PresentationSession.makeError(str: "Unable to encode credential offer")
		}
		let metadataResolver = OpenId4VciService.makeMetadataResolver(networkingVci)
		let authorizationResolver = AuthorizationServerMetadataResolver(
			oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networkingVci),
			oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networkingVci)
		)
		let resolver = CredentialOfferRequestResolver(
			fetcher: Fetcher<CredentialOfferRequestObject>(session: networkingVci),
			credentialIssuerMetadataResolver: metadataResolver,
			authorizationServerMetadataResolver: authorizationResolver
		)
		let result = await resolver.resolve(source: .passByValue(metaData: normalizedOffer), policy: policy)
		do { return try result.get() }
		catch { throw PresentationSession.makeError(str: "Unable to resolve credential offer: \(error.localizedDescription)") }
	}

/// Resolve OpenID4VCI offer URL document types. Resolved offer metadata are cached
	/// When resolving an offer, defaultKeyOptions are now included
	/// - Parameters:
	///   - uriOffer: url with offer
	/// - Returns: Offered issue information model
	public func resolveOfferUrlDocTypes(offerUri: String, authFlowRedirectionURI: URL?) async throws -> OfferedIssuanceModel {
		// Resolve every explicit inspection under the currently registered policy.
		// Reusing an older offer here could bypass a newly strengthened signed-metadata policy.
		let offer = try await resolveCredentialOffer(offerUri: offerUri)
		let credentialIssuerIdentifier = offer.credentialIssuerIdentifier
		let urlString = credentialIssuerIdentifier.url.absoluteString
		// CHECK: Must be pre-registered in registry
		let vciService: OpenId4VciService
		if let registeredService = openId4VciServiceRegistry.getByIssuerURL(urlString) {
			await registeredService.setWalletTransactionLogger(transactionLogger)
			vciService = registeredService
		} else {
			vciService = try await autoRegisterVciConfiguration(urlString, authFlowRedirectionURI)
		}
		return try await vciService.resolveOfferDocTypes(offerUri: offerUri, offer: offer)
	}

	/// Issue documents by offer URI.
	/// - Parameters:
	///   - offerUri: url with offer
	///   - docTypes: offered doc models available to be issued. Contains key options (secure are name and other options)
	///   - txCodeValue: Transaction code given to user (if available)
	///   - promptMessage: prompt message for biometric authentication (optional)
	///  - configuration: Optional OpenId4VciConfiguration to override the default one for this issuance
	/// - Returns: Array of issued and stored documents
	public func issueDocumentsByOfferUrl(offerUri: String, docTypes: [OfferedDocModel], txCodeValue: String? = nil, promptMessage: String? = nil, configuration: OpenId4VciConfiguration? = nil) async throws -> [WalletStorage.Document] {
		let offer: CredentialOffer
		if configuration == nil, let cachedOffer = openId4VciCache.takeCredentialOffer(for: offerUri) {
			offer = cachedOffer
		} else {
			offer = try await resolveCredentialOffer(
				offerUri: offerUri,
				policyOverride: configuration?.issuerMetadataPolicy
			)
		}
		let urlString = offer.credentialIssuerIdentifier.url.absoluteString
		let vciService: OpenId4VciService
		if let configuration {
			// The issuer in the resolved offer is authoritative. Preserve the
			// caller's remaining settings in a service scoped to this operation.
			vciService = try makeEphemeralOpenId4VciService(
				issuerURL: urlString,
				configuration: configuration
			)
		} else {
			vciService = try await resolveVCIService(issuerName: urlString)
		}
		return try await vciService.issueDocumentsByOfferUrl(offerUri: offerUri, resolvedOffer: offer, docTypes: docTypes, authorized: nil, documentId: nil, txCodeValue: txCodeValue, promptMessage: promptMessage)
	}

	/// Begin issuing a document by generating an issue request
	///
	/// - Parameters:
	///   - id: Document identifier
	///   - credentialOptions: Credential options specifying batch size and credential policy
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	///   - bDeferred: Whether this is for deferred issuance (default: false)
	/// - Returns: An issue request object that can be used to complete the issuance process
	public func beginIssueDocument(id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions?, bDeferred: Bool = false) async throws -> IssueRequest {
		let request = try IssueRequest(id: id, credentialOptions: credentialOptions, keyOptions: keyOptions)
		return request
	}

	/// End issuing by saving the issuing document (and its private key) in storage
	/// - Parameter issued: The issued document
	public func endIssueDocument(_ issued: WalletStorage.Document, batch: [WalletStorage.Document]?) async throws {
		try await storage.storageService.saveDocument(issued, batch: batch, allowOverwrite: true)
	}

	/// Load documents with a specific status from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	/// - Parameter status: Status of documents to load
	@discardableResult public func loadDocuments(status: WalletStorage.DocumentStatus) async throws -> [WalletStorage.Document]? {
		return try await storage.loadDocuments(status: status, uiCulture: eudiWalletConfig.uiCulture)
	}

	/// Load all documents from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: An array of ``WalletStorage.Document`` objects
	/// - Parameter status: Status of documents to load
	@discardableResult public func loadAllDocuments() async throws -> [WalletStorage.Document]? {
		var res: [WalletStorage.Document]?
		for status in WalletStorage.DocumentStatus.allCases {
			if let docs = (try await loadDocuments(status: status)) {
				res = (res ?? []) + docs
			}
		}
		return res
	}

	/// Load a document with a specific status from storage
	///
	/// Calls ``storage`` loadDocuments
	/// - Returns: A `WalletStorage.Document` object
	/// - Parameter status: Status of document to load
	@discardableResult public func loadDocument(id: String, status: WalletStorage.DocumentStatus) async throws -> WalletStorage.Document? {
		return try await storage.loadDocument(id: id, uiCulture: eudiWalletConfig.uiCulture, status: status)
	}

	/// Delete documents with a specified status from storage
	///
	/// Calls ``storage`` deleteDocuments
	/// - Parameter status: Status of documents to delete
	public func deleteDocuments(status: WalletStorage.DocumentStatus) async throws  {
		let docInfos = await getDocumentInfos(for: status)
		do {
			try await storage.deleteDocuments(status: status)
			for info in docInfos { await logDeletionTransaction(info: info, status: .completed) }
		} catch {
			for info in docInfos { await logDeletionTransaction(info: info, status: .failed, errorMessage: error.localizedDescription) }
			throw error
		}
	}

	/// Delete all documents
	public func deleteAllDocuments() async throws {
		for status in WalletStorage.DocumentStatus.allCases {
			try await deleteDocuments(status: status)
		}
	}

	/// Delete document by id

	/// Deletes a document with the specified ID and status.
	/// - Parameters:
	///   - id: The unique identifier of the document to be deleted.
	///   - status: The current status of the document.
	///
	/// - Throws: An error if the document could not be deleted.
	public func deleteDocument(id: String, status: DocumentStatus) async throws {
		let info = await getDocumentInfos(for: status).first(where: { $0.id == id })
		do {
			try await storage.deleteDocument(id: id, status: status)
			await logDeletionTransaction(info: info, status: .completed)
		} catch {
			await logDeletionTransaction(info: info, status: .failed, errorMessage: error.localizedDescription)
			throw error
		}
	}

	private struct DocumentInfo {
		let id: String
		let docType: String?
		let displayName: String?
		let dataFormat: DocDataFormat
	}

	@MainActor private func getDocumentInfos(for status: DocumentStatus) -> [DocumentInfo] {
		switch status {
		case .issued:
			return storage.docModels.map { DocumentInfo(id: $0.id, docType: $0.docType, displayName: $0.displayName, dataFormat: $0.docDataFormat) }
		case .pending:
			return storage.pendingDocuments.map { DocumentInfo(id: $0.id, docType: $0.docType, displayName: $0.displayName, dataFormat: $0.docDataFormat) }
		case .deferred:
			return storage.deferredDocuments.map { DocumentInfo(id: $0.id, docType: $0.docType, displayName: $0.displayName, dataFormat: $0.docDataFormat) }
		}
	}

	private func logDeletionTransaction(info: DocumentInfo?, status: TransactionLog.Status, errorMessage: String? = nil) async {
		// TODO: Should we log the deletion event even if the document info is not found?
		guard let transactionLogger, let info else { return }
		let transactionLog = TransactionLog(timestamp: TransactionLogUtils.getTimestamp(),
			status: status, errorMessage: errorMessage, type: .deletion,
			dataFormat: TransactionLog.DataFormat(info.dataFormat), documentId: info.id, docType: info.docType, displayName: info.displayName)
		do {
			try await transactionLogger.log(transaction: transactionLog)
		} catch {
			logger.error("Failed to log deletion transaction: \(error)")
		}
	}

	/// Get a document's remaining credentials, available for presentation count
	///
	/// - Parameters:
	///   - id: The unique identifier of the document to check usage counts for
	/// - Returns: A `CredentialsUsageCounts` object containing total and remaining presentation counts  if the document uses a one-time use policy, or `nil` if the document uses a rotate-use          policy (unlimited presentations)
	@available(*, deprecated, message: "Use credentialsUsageCount property of the DocClaimDecodable model instead")
	public func getCredentialsUsageCount(id: String) async throws -> CredentialsUsageCounts? {
		let uc = try await storage.getCredentialsUsageCount(id: id)
		await storage.setUsageCount(uc, id: id)
		return uc
	}

	/// Refresh usage counters for all loaded issued documents.
	///
	/// This method updates the usage counters in `storage.docModels` based on the secure area key batch state.
	/// This is typically used to synchronize the wallet's cached counter values with the actual state on the device.
	/// If a counter value changes, the corresponding document model publishes the change, allowing SwiftUI views
	/// to automatically update.
	///
	/// Use this method when your app returns to the foreground to ensure that any presentations that occurred
	/// in other apps are reflected in the wallet's document counters.
	///
	/// - Throws: An error if the refresh operation fails.
	///
	/// ```swift
	/// .onReceive(NotificationCenter.default.publisher(for: UIApplication.willEnterForegroundNotification)) { _ in
	///     Task { try? await wallet.refreshUsageCounters() }
	/// }
	/// ```
	public func refreshUsageCounters() async throws {
		try await storage.refreshUsageCounters()
	}

	/// Prepare Service Data Parameters
	/// - Parameters:
	///   - docType: docType of documents to present (optional)
	/// - Returns: An ``InitializeTransferData`` instance that can be used to initialize a presentation service
	public func prepareServiceDataParameters(format: DocDataFormat? = nil) async throws -> (InitializeTransferData, [WalletStorage.Document]) {
		var parameters: InitializeTransferData
		guard var docs = try await storage.storageService.loadDocuments(status: .issued), docs.count > 0 else {
			// TODO: localizationKey is kept for backward compatibility — clients can migrate to use `code` instead
			throw PresentationSession.makeError(str: PresentationSession.NotAvailableStr, localizationKey: "request_data_no_document", code: .noDocumentsAvailable)
		}
		if let format { docs = docs.filter { $0.docDataFormat == format } }
		let idsToDocData = docs.compactMap { $0.getDataForTransfer() }
		var docKeyInfos = Dictionary(uniqueKeysWithValues: idsToDocData.map(\.docKeyInfo))
		var docData = Dictionary(uniqueKeysWithValues: idsToDocData.map(\.doc))
		var documentKeyIndexes = docData.mapValues { _ in 0 }
		var usableDocumentIds = Set<String>()
		for doc0 in docs {
			// find the credential to use based on usage counts and policy
			guard let dkid = docKeyInfos[doc0.id], let dki = DocKeyInfo(from: dkid) else { continue }
			let kbi = try await SecureAreaRegistry.shared.get(name: dki.secureAreaName).getKeyBatchInfo(id: doc0.id)
			if let dclaims = await storage.getDocumentModel(id: doc0.id),
				let validUntil = dclaims.validUntil,
				validUntil < .now {
				continue
			}
			if kbi.batchSize <= 1 {
				if kbi.credentialPolicy == .oneTimeUse,
					(kbi.usedCounts.first ?? 1) > 0 {
					continue
				}
			} else {
				guard let selectedDocument = try await storage.storageService.loadDocument(id: doc0.id, status: .issued) else {
					continue
				}
				docData[doc0.id] = selectedDocument.data
				documentKeyIndexes[doc0.id] = selectedDocument.keyIndex
			}
			usableDocumentIds.insert(doc0.id)
		}
		docs = docs.filter { usableDocumentIds.contains($0.id) }
		docKeyInfos = docKeyInfos.filter { usableDocumentIds.contains($0.key) }
		docData = docData.filter { usableDocumentIds.contains($0.key) }
		documentKeyIndexes = documentKeyIndexes.filter { usableDocumentIds.contains($0.key) }
		let usableTransferData = idsToDocData.filter { usableDocumentIds.contains($0.doc.0) }
		guard !docs.isEmpty, !docData.isEmpty else {
			// TODO: localizationKey is kept for backward compatibility — clients can migrate to use `code` instead
			throw PresentationSession.makeError(str: PresentationSession.NotAvailableStr, localizationKey: "request_data_no_document", code: .noDocumentsAvailable)
		}
		let docMetadata = Dictionary(uniqueKeysWithValues: usableTransferData.map(\.metadata))
		let idsToDocTypes = Dictionary(uniqueKeysWithValues: docs.map { ($0.id, $0.docType) })
		let docDisplayNames = Dictionary(uniqueKeysWithValues: docs.map { ($0.id, $0.getClaimDisplayNames(eudiWalletConfig.uiCulture)) })
		let jwtHashingAlgs = Dictionary(uniqueKeysWithValues: docs.map { ($0.id, SdJwtUtils.getHashingAlgorithm(doc: $0))}).compactMapValues { $0 }
		let iaca = eudiWalletConfig.trustedReaderRootCertificates ?? []
		let dataFormats = Dictionary(uniqueKeysWithValues: usableTransferData.map(\.fmt))
		let deviceAuthMethod = eudiWalletConfig.deviceAuthMethod.rawValue
		parameters = InitializeTransferData(dataFormats: dataFormats, documentData: docData, documentKeyIndexes: documentKeyIndexes, docMetadata: docMetadata, docDisplayNames: docDisplayNames, docKeyInfos: docKeyInfos, iaca: iaca, deviceAuthMethod: deviceAuthMethod, idsToDocTypes: idsToDocTypes, hashingAlgs: jwtHashingAlgs, bleTransferMode: bleTransferMode, crlRevocationPolicy: eudiWalletConfig.crlRevocationPolicy, zkSystemRepository: zkSystemRepository)
		return (parameters, docs)
	}

	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - flow: Presentation ``FlowType`` instance
	///   - docType: DocType of documents to present (optional)
	/// - Returns: A presentation session instance,
	public func beginPresentation(flow: FlowType, sessionTransactionLogger: (any TransactionLogger)? = nil) async -> PresentationSession {
		do {
			let (parameters, documents) = try await prepareServiceDataParameters(format: flow == .ble ? .cbor : nil)
			let docIdToPresentInfo = try await storage.getDocIdsToPresentInfo(documents: documents)
			let mergedTransactionLogger = sessionTransactionLogger ?? transactionLogger
			let storageService = storage.storageService
			switch flow {
			case .ble:
				let bleSvc = try await BlePresentationService(parameters: parameters)
				return PresentationSession(presentationService: bleSvc, storageManager: storage, storageService: storageService, docIdToPresentInfo: docIdToPresentInfo, documentKeyIndexes: parameters.documentKeyIndexes, userAuthenticationRequired: eudiWalletConfig.userAuthenticationRequired, transactionLogger: mergedTransactionLogger)
			case .openid4vp(let qrCode):
				let openIdSvc = try await OpenId4VpService(
					parameters: parameters,
					qrCode: qrCode,
					openID4VpConfig: self.openID4VpConfig,
					networking: networkingVp,
					crlRevocationPolicy: eudiWalletConfig.crlRevocationPolicy
				)
				return PresentationSession(presentationService: openIdSvc, storageManager: storage, storageService: storageService, docIdToPresentInfo: docIdToPresentInfo, documentKeyIndexes: parameters.documentKeyIndexes, userAuthenticationRequired: eudiWalletConfig.userAuthenticationRequired, transactionLogger: mergedTransactionLogger)
			default:
				let fallbackError = PresentationSession.makeError(str: "Use beginPresentation(service:)")
				let faultService = FaultPresentationService(error: fallbackError)
				return PresentationSession(presentationService: faultService, storageManager: storage, storageService: storageService, docIdToPresentInfo: docIdToPresentInfo, documentKeyIndexes: parameters.documentKeyIndexes, userAuthenticationRequired: false, transactionLogger: mergedTransactionLogger)
			}
		} catch {
			let faultService = FaultPresentationService(error: error)
			let mergedTransactionLogger = sessionTransactionLogger ?? transactionLogger
			return PresentationSession(presentationService: faultService, storageManager: storage, storageService: storage.storageService, docIdToPresentInfo: [:], documentKeyIndexes: [:], userAuthenticationRequired: false, transactionLogger: mergedTransactionLogger)
		}
	}

	/// Begin attestation presentation to a verifier
	/// - Parameters:
	///   - service: An instance conforming to the ``PresentationService`` protocol that will
	///    be used to handle the presentation.
	///   - docType: DocType of documents to present (optional)
	/// - Returns: A `PresentationSession` instance,
	public func beginPresentation(service: any PresentationService, sessionTransactionLogger: TransactionLogger?) async -> PresentationSession {
		do {
			let (parameters, documents) = try await prepareServiceDataParameters()
			let docIdToPresentInfo = try await storage.getDocIdsToPresentInfo(documents: documents)
			let mergedTransactionLogger = sessionTransactionLogger ?? self.transactionLogger
			return PresentationSession(presentationService: service, storageManager: storage, storageService: storage.storageService, docIdToPresentInfo: docIdToPresentInfo, documentKeyIndexes: parameters.documentKeyIndexes, userAuthenticationRequired: eudiWalletConfig.userAuthenticationRequired, transactionLogger: mergedTransactionLogger)
		} catch {
			let faultService = FaultPresentationService(error: error)
			let mergedTransactionLogger = sessionTransactionLogger ?? transactionLogger
			return PresentationSession(presentationService: faultService, storageManager: storage, storageService: storage.storageService, docIdToPresentInfo: [:], documentKeyIndexes: [:], userAuthenticationRequired: false, transactionLogger: mergedTransactionLogger)
		}
	}

	/// Perform an action after user authorization via TouchID/FaceID/Passcode
	/// - Parameters:
	///   - dismiss: Action to perform if the user cancels authorization
	///   - action: Action to perform after user authorization
	public nonisolated static func authorizedAction<T: Sendable>(action: sending () async throws -> T, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws -> T? {
		return try await authorizedAction(isFallBack: false, action: action, disabled: disabled, dismiss: dismiss, localizedReason: localizedReason)
	}

	/// Parse transaction log
	public func parseTransactionLog(_ transactionLog: TransactionLog) -> TransactionLogData {
		switch transactionLog.type {
			case .presentation: .presentation(log: PresentationLogData(transactionLog, uiCulture: eudiWalletConfig.uiCulture))
			case .issuance: .issuance(log: IssuanceLogData(transactionLog))
			case .deletion: .deletion(log: DeletionLogData(transactionLog))
			case .signing: .signing
		}
	}

	/// Get document status from a signed status list.
	///
	/// - Important: A signature `verifier` is required before status-list claims
	///   are accepted.
	/// - Parameters:
	///   - statusIdentifier: Index and URL of the credential's status-list entry.
	///   - verifier: Verifies the status-list token before its claims are used.
	///   - date: Evaluation time used for token validity checks.
	///   - clockSkew: Allowed token-validity clock skew, in seconds.
	public func getDocumentStatus(
		for statusIdentifier: StatusIdentifier,
		verifier: any VerifyStatusListTokenSignature,
		date: Date = .now,
		clockSkew: TimeInterval = 60
	) async throws -> CredentialStatus {
		let actor = DocumentStatusService(
			statusIdentifier: statusIdentifier,
			date: date,
			clockSkew: clockSkew,
			verifier: verifier,
			networkingService: StatusNetworkingAdapter(networking: networkingVci.networking)
		)
		let status = try await actor.getStatus()
		return status
	}

	/// Compatibility overload. Status-list claims are never accepted without a
	/// caller-provided signature verifier.
	@available(*, deprecated, message: "Pass a status-list signature verifier explicitly")
	public func getDocumentStatus(
		for statusIdentifier: StatusIdentifier,
		verifier: (any VerifyStatusListTokenSignature)? = nil,
		date: Date = .now,
		clockSkew: TimeInterval = 60
	) async throws -> CredentialStatus {
		guard let verifier else {
			throw WalletError(description: "A status-list signature verifier is required; use the verifier overload")
		}
		return try await getDocumentStatus(for: statusIdentifier, verifier: verifier, date: date, clockSkew: clockSkew)
	}

	/// Executes an authorized action with optional fallback and dismissal handling.
	/// The action is performed after successful biometric authentication (TouchID or FaceID).
	///
	/// - Parameters:
	///   - isFallBack: A Boolean value indicating whether the action is a fallback after failed biometric authentication
	///  (ask for pin code). Default is `false`.
	///   - action: An asynchronous closure that performs the action and returns a result of type `T`.
	///   - disabled: A Boolean value indicating whether the action is disabled.
	///   - dismiss: A closure that handles the dismissal of the action.
	///   - localizedReason: A localized string providing the reason for the authorization request.
	///
	/// - Returns: An optional result of type `T` if the action is successful, otherwise `nil`.
	///
	/// - Throws: An error if the action fails.
	static nonisolated func authorizedAction<T: Sendable>(isFallBack: Bool = false, action: sending () async throws -> T, disabled: Bool, dismiss: () -> Void, localizedReason: String) async throws -> T? {
		guard !disabled else {
			return try await action()
		}
		let context = LAContext()
		var error: NSError?
		let policy: LAPolicy = .deviceOwnerAuthentication
		if context.canEvaluatePolicy(policy, error: &error) {
			do {
				let success = try await context.evaluatePolicy(policy, localizedReason: localizedReason)
				#if os(iOS)
				if success, let scene = await UIApplication.shared.connectedScenes.first {
					let activateState = await scene.activationState
					if activateState != .foregroundActive {
					  // Delay the task by 1 second if not foreground
						try await Task.sleep(nanoseconds: 1_000_000_000)
					}
					return try await action()
				}
				else { dismiss(); }
				#else
				if success { return try await action() }
				#endif
			} catch let laError as LAError {
				if !isFallBack, laError.code == .userFallback {
					return try await authorizedAction(isFallBack: true, action: action, disabled: disabled, dismiss: dismiss, localizedReason: localizedReason)
				} else {
					dismiss()
					return nil
				}
			}
		} else if let error {
			throw PresentationSession.makeError(str: error.localizedDescription)
		}
		return nil
	}
}

