/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation
import OpenID4VCI
import JOSESwift
import MdocDataModel18013
import MdocSecurity18013
import AuthenticationServices
import Logging
import CryptoKit
import Security
import WalletStorage
import SwiftCBOR
import JOSESwift
import SwiftyJSON
import LocalAuthentication
import X509
import class eudi_lib_sdjwt_swift.ClaimsVerifier
import class eudi_lib_sdjwt_swift.CompactParser
import class eudi_lib_sdjwt_swift.SDJWTVerifier
import class eudi_lib_sdjwt_swift.SdJwtVcIssuerMetaDataFetcher
import class eudi_lib_sdjwt_swift.SignatureVerifier
import protocol eudi_lib_sdjwt_swift.KeyExpressible
import struct eudi_lib_sdjwt_swift.SignedSDJWT

private struct IndexedIssuedDocument: Sendable {
	let index: Int
	let document: WalletStorage.Document
}

public actor OpenId4VciService {
	static let maximumCredentialBatchSize = 100
	var issueReq: IssueRequest!
	let uiCulture: String?
	let logger: Logger
	let config: OpenId4VciConfiguration
	let cache: OpenId4VciCache
	var cachedIssuerMetadata: (url: String, value: (CredentialIssuerId, CredentialIssuerMetadata))?
	var networking: any Networking
	let responseLimitedNetworking: any BoundedNetworkingProtocol
	var authRequested: AuthorizationRequested?
	private var activeIssuanceOperation: UUID?
	var keyBatchSize: Int { issueReq.credentialOptions.batchSize }
	var storage: StorageManager
	var storageService: any DataStorageService
	var transactionLogger: (any TransactionLogger)?
	@MainActor var simpleAuthWebContext: SimpleAuthenticationPresentationContext!
	@MainActor var authenticationSession: ASWebAuthenticationSession?
	typealias FuncKeyAttestationJWT = @Sendable (_ nonce: String?) async throws -> KeyAttestationJWT

	init(uiCulture: String?, config: OpenId4VciConfiguration, networking: any Networking, storage: StorageManager, storageService: any DataStorageService, transactionLogger: (any TransactionLogger)? = nil, cache: OpenId4VciCache = OpenId4VciCache()) throws {
		logger = Logger(label: "OpenId4VCI")
		guard let issuer = config.credentialIssuerURL, let issuerURL = URL(string: issuer) else {
			throw PresentationSession.makeError(str: "credentialIssuerURL must be set to a valid URL in OpenId4VciConfiguration")
		}
		try EudiWallet.validateHTTPSRemoteURL(issuerURL, purpose: "Credential issuer")
		self.uiCulture = uiCulture
		if let wrapper = networking as? OpenID4VCINetworking {
			self.networking = wrapper
			self.responseLimitedNetworking = wrapper.networking
		} else if let limited = networking as? any BoundedNetworkingProtocol {
			let wrapper = OpenID4VCINetworking(networking: limited)
			self.networking = wrapper
			self.responseLimitedNetworking = limited
		} else {
			throw PresentationSession.makeError(str: "Issuance networking must support bounded response streaming")
		}
		self.storage = storage
		self.storageService = storageService
		self.config = config
		self.transactionLogger = transactionLogger
		self.cache = cache
	}

	func setWalletTransactionLogger(_ transactionLogger: (any TransactionLogger)?) {
		self.transactionLogger = transactionLogger
	}

	/// Prepare issuing by creating an issue request (id, private key) and an OpenId4VCI service instance
	/// - Parameters:
	///   - docType: document type
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: (Issue request key pair, vci service, unique id)
	func prepareIssuing(id: String, docTypeIdentifier: DocTypeIdentifier, displayName: String?, credentialOptions: CredentialOptions, keyOptions: KeyOptions?, disablePrompt: Bool, promptMessage: String?, offer: CredentialOffer? = nil) async throws {
		let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions, offer: offer)
		try Self.validateBatchSize(usedCredentialOptions.batchSize)
		let resolvedDocTypeName = displayName ?? docTypeIdentifier.docTypeOrVct ?? docTypeIdentifier.value
		let localizedDocTypeName = NSLocalizedString(resolvedDocTypeName, comment: "")
		let defaultLocalizedReason = NSLocalizedString("issue_document", comment: "")
		let localizedReason = promptMessage ?? defaultLocalizedReason.replacingOccurrences(of: "{docType}", with: localizedDocTypeName)
		issueReq = try await EudiWallet.authorizedAction(action: {
			return try beginIssueDocument(id: id, credentialOptions: usedCredentialOptions, keyOptions: keyOptions)
		}, disabled: !config.userAuthenticationRequired || disablePrompt, dismiss: {}, localizedReason: localizedReason)
		guard issueReq != nil else {
			logger.error("User cancelled authentication")
			throw LAError(.userCancel)
		}
	}

	// create batch keys and return the binding keys and the `CoseKey` public keys in cbor format
	func initSecurityKeys(_ configuration: CredentialConfiguration, proofSubject: String) async throws -> ([BindingKey], [Data]) {
		let algSupported = Set(configuration.credentialSigningAlgValuesSupported)
		// Convert credential issuer supported algorithms to JWSAlgorithm types
		let algTypes = algSupported.compactMap { JWSAlgorithm.AlgorithmType(rawValue: $0) }
		guard !algTypes.isEmpty else {
			throw PresentationSession.makeError(str: "No valid signing algorithms found in credential metadata: \(algSupported)")
		}
		// Find a compatible signing algorithm that both the secure area and credential issuer support
		let selectedAlgorithm = try findCompatibleSigningAlgorithm(algSupported: algTypes)
		guard let algType = Self.mapToJWSAlgorithmType(selectedAlgorithm) else {
			throw PresentationSession.makeError(str: "Unsupported secure area signing algorithm: \(selectedAlgorithm)")
		}
		let publicCoseKeys = try await issueReq.createKeyBatch()
		do {
			let publicKeys = try Self.makePublicJwks(from: publicCoseKeys, algorithm: algType)
			let unlockData = try await issueReq.secureArea.unlockKey(id: issueReq.id)
			var funcKeyAttestationJWT: FuncKeyAttestationJWT? = nil
			if config.keyAttestationsConfig != nil, configuration.supportsAttestationProofType {
				funcKeyAttestationJWT = { nonce in
					try await self.getKeyAttestationJWTForWalletAppCompatibility(publicKeys, nonce: nonce)
				}
			} else if config.keyAttestationsConfig != nil, configuration.supportsJwtProofTypeWithAttestation {
				throw PresentationSession.makeError(str: "JWT proof with attestation is not yet supported in wallet")
			}
			if let funcKeyAttestationJWT {
				return (
					[.attestation(keyAttestationJWT: funcKeyAttestationJWT)],
					publicCoseKeys.map { Data($0.toCBOR(options: CBOROptions()).encode()) }
				)
			} else {
				let bindingKeys = try publicKeys.enumerated().map { try createBindingKey($0.element, secureAreaSigningAlg: selectedAlgorithm, unlockData: unlockData, index: $0.offset, funcKeyAttestationJWT: nil, proofSubject: proofSubject) }
				return (bindingKeys, publicCoseKeys.map { Data($0.toCBOR(options: CBOROptions()).encode()) })
			}
		} catch {
			await cleanupIssueRequestKeys()
			throw error
		}
	}

	func createKeyBatchWithAttestation(id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions?, nonce: String?) async throws -> BatchCreateKeyResult {
		try Self.validateBatchSize(credentialOptions.batchSize)
		guard let attestationProvider = config.keyAttestationsConfig?.walletAttestationsProvider else {
			throw PresentationSession.makeError(str: "Key attestations are not configured for issuer \(config.credentialIssuerURL ?? "unknown")")
		}
		let request = try IssueRequest(id: id, credentialOptions: credentialOptions, keyOptions: keyOptions)
		do {
			let publicCoseKeys = try await request.createKeyBatch()
			let publicKeys = try Self.makePublicJwks(from: publicCoseKeys)
			let keyAttestation = try await attestationProvider.getKeysAttestation(keys: publicKeys, nonce: nonce)
			return BatchCreateKeyResult(keys: publicCoseKeys, keyAttestation: keyAttestation)
		} catch {
			try? await request.secureArea.deleteKeyBatch(id: id, startIndex: 0, batchSize: credentialOptions.batchSize)
			try? await request.secureArea.deleteKeyInfo(id: id)
			throw error
		}
	}

	static func validateBatchSize(_ batchSize: Int) throws {
		guard (1...maximumCredentialBatchSize).contains(batchSize) else {
			throw PresentationSession.makeError(
				str: "Credential batch size must be between 1 and \(maximumCredentialBatchSize)"
			)
		}
	}

	static func validateAuthorizationState(_ receivedState: String?, expectedState: String) throws -> String {
		guard let receivedState, receivedState == expectedState else {
			throw PresentationSession.makeError(str: "Authorization response state is missing or does not match the request")
		}
		return receivedState
	}

	private static func encodedOptionsMatch<T: Encodable>(_ lhs: T, _ rhs: T) -> Bool {
		let encoder = JSONEncoder()
		encoder.outputFormatting = [.sortedKeys]
		guard let lhsData = try? encoder.encode(lhs), let rhsData = try? encoder.encode(rhs) else {
			return false
		}
		return lhsData == rhsData
	}

	func cleanupIssueRequestKeys() async {
		guard let issueReq else { return }
		try? await issueReq.secureArea.deleteKeyBatch(
			id: issueReq.id,
			startIndex: 0,
			batchSize: issueReq.credentialOptions.batchSize
		)
		try? await issueReq.secureArea.deleteKeyInfo(id: issueReq.id)
	}

	func beginExclusiveIssuanceOperation() throws -> UUID {
		guard activeIssuanceOperation == nil else {
			throw PresentationSession.makeError(str: "Another issuance operation is already in progress for this issuer")
		}
		let token = UUID()
		activeIssuanceOperation = token
		return token
	}

	func endExclusiveIssuanceOperation(_ token: UUID) {
		if activeIssuanceOperation == token { activeIssuanceOperation = nil }
	}

	func beginIssuanceResume(id: String, status: DocumentStatus) throws {
		try IssuanceResumeLeaseRegistry.shared.acquire(storage: storageService, documentId: id)
	}

	func endIssuanceResume(id: String, status: DocumentStatus) {
		IssuanceResumeLeaseRegistry.shared.release(storage: storageService, documentId: id)
	}

	func hasStoredDocument(id: String, status: DocumentStatus) async throws -> Bool {
		try await storageService.loadDocuments(status: status)?.contains { $0.id == id } == true
	}

	func persistedPlaceholder(matching candidate: WalletStorage.Document, status: DocumentStatus) async throws -> WalletStorage.Document {
		guard let stored = try await storageService.loadDocuments(status: status)?.first(where: { $0.id == candidate.id }) else {
			throw PresentationSession.makeError(str: "Issuance document is no longer pending in storage")
		}
		guard stored.data == candidate.data,
			stored.metadata == candidate.metadata,
			stored.docKeyInfo == candidate.docKeyInfo else {
			throw PresentationSession.makeError(str: "The supplied issuance document is stale")
		}
		return stored
	}

	func validateConfiguredIssuer(_ issuer: String) throws {
		guard let configuredIssuer = config.credentialIssuerURL,
			Self.normalizedIssuerIdentifier(issuer) == Self.normalizedIssuerIdentifier(configuredIssuer) else {
			throw PresentationSession.makeError(str: "Issuance document belongs to a different credential issuer")
		}
	}

	static func normalizedIssuerIdentifier(_ value: String) -> String? {
		guard var components = URLComponents(string: value),
			let scheme = components.scheme?.lowercased(),
			let host = components.host?.lowercased() else { return nil }
		components.scheme = scheme
		components.host = host
		components.fragment = nil
		if scheme == "https", components.port == 443 { components.port = nil }
		while components.path.count > 1, components.path.hasSuffix("/") { components.path.removeLast() }
		return components.url?.absoluteString
	}

	private static func makePublicJwks(from publicCoseKeys: [CoseKey], algorithm: JWSAlgorithm.AlgorithmType? = nil) throws -> [ECPublicKey] {
		try publicCoseKeys.map {
			var additionalParameters: [String: String] = ["use": "sig", "kid": UUID().uuidString]
			if let algorithm {
				additionalParameters["alg"] = JWSAlgorithm(algorithm).name
			}
			return try ECPublicKey(publicKey: try $0.toSecKey(), additionalParameters: additionalParameters)
		}
	}

	func getKeyAttestationJWT(_ publicKeys: [ECPublicKey], nonce: String?) async throws -> KeyAttestationJWT {
		guard let keyAttestationsConfig = config.keyAttestationsConfig else {
			throw PresentationSession.makeError(str: "Key attestations are not configured")
		}
		let jwt = try await keyAttestationsConfig.walletAttestationsProvider.getKeysAttestation(keys: publicKeys, nonce: nonce)
		let keyAttestationJwt: KeyAttestationJWT = try .init(jws: .init(compactSerialization: jwt))
		return keyAttestationJwt
	}

	func createBindingKey(_ publicKeyJWK: ECPublicKey, secureAreaSigningAlg: MdocDataModel18013.SigningAlgorithm, unlockData: Data?, index: Int, funcKeyAttestationJWT: FuncKeyAttestationJWT?, proofSubject: String) throws -> BindingKey {
		guard let algType = Self.mapToJWSAlgorithmType(secureAreaSigningAlg) else {
			throw PresentationSession.makeError(str: "Unsupported proof signing algorithm: \(secureAreaSigningAlg)")
		}
		let signer = try SecureAreaSigner(secureArea: issueReq.secureArea, id: issueReq.id, index: index, publicKey: publicKeyJWK, curve: publicKeyJWK.crv.coseEcCurve, ecAlgorithm: secureAreaSigningAlg, unlockData: unlockData)
		let bindingKey: BindingKey
		if let funcKeyAttestationJWT {
			bindingKey = try .jwtKeyAttestation(algorithm: JWSAlgorithm(algType), keyAttestationJWT: funcKeyAttestationJWT, keyIndex: UInt(index), privateKey: .custom(signer), issuer: proofSubject)
		} else {
			bindingKey = .jwt(algorithm: JWSAlgorithm(algType), jwk: publicKeyJWK, privateKey: .custom(signer), issuer: proofSubject)
		}
		return bindingKey
	}

	func createKeyBatch() async throws {
		_ = try await issueReq.createKeyBatch()
	}

	func clearCachedOfferMetadata(offerUri: String? = nil) {
		if let offerUri { cache.removeCredentialOffer(for: offerUri) }
		else { cache.removeAllCredentialOffers() }
	}

	/// Clear the issuer metadata cache
	func clearIssuerMetadataCache() {
		cachedIssuerMetadata = nil
	}

	public nonisolated func beginIssueDocument(id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions?, bDeferred: Bool = false) throws -> IssueRequest {
		let ir = try IssueRequest(id: id, credentialOptions: credentialOptions, keyOptions: keyOptions)
		return ir
	}

	/// End issuing by saving the issuing document (and its private key) in storage
	/// - Parameter issued: The issued document
	public func endIssueDocument(_ issued: WalletStorage.Document, batch: [WalletStorage.Document]?) async throws {
		try await storageService.saveDocument(issued, batch: batch, allowOverwrite: true)
	}

	public func resolveOfferUrlDocTypes(offerUri: String) async throws -> OfferedIssuanceModel {
		let fetcher = Fetcher<CredentialOfferRequestObject>(session: networking)
		let metadataResolver = Self.makeMetadataResolver(networking)
		let oidcFetcher = Fetcher<OIDCProviderMetadata>(session: networking)
		let oauthFetcher = Fetcher<AuthorizationServerMetadata>(session: networking)
		let authorizationResolver = AuthorizationServerMetadataResolver(oidcFetcher: oidcFetcher, oauthFetcher: oauthFetcher)
		let resolver = CredentialOfferRequestResolver(fetcher: fetcher, credentialIssuerMetadataResolver: metadataResolver, authorizationServerMetadataResolver: authorizationResolver)
		let source = try CredentialOfferRequest(urlString: offerUri)
		if case .fetchByReference(let url) = source {
			try EudiWallet.validateHTTPSRemoteURL(url, purpose: "Credential offer reference")
		}
		let result = await resolver.resolve(source: source, policy: config.issuerMetadataPolicy)
		switch result {
		case .success(let offer):
			try EudiWallet.validateHTTPSRemoteURL(offer.credentialIssuerIdentifier.url, purpose: "Credential issuer")
			try validateConfiguredIssuer(offer.credentialIssuerIdentifier.url.absoluteString)
			return try await resolveOfferDocTypes(offerUri: offerUri, offer: offer)
		case .failure(let error):
			throw PresentationSession.makeError(str: "Unable to resolve credential offer: \(error.localizedDescription)")
		}
	}

	/// Resolve issue offer and return available document metadata
	/// - Parameters:
	///   - uriOffer: Uri of the offer (from a QR or a deep link)
	///   - format: format of the exchanged data
	/// - Returns: The data of the document
	public func resolveOfferDocTypes(offerUri: String, offer: CredentialOffer) async throws -> OfferedIssuanceModel {
		try validateConfiguredIssuer(offer.credentialIssuerIdentifier.url.absoluteString)
		let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
		cache.store(offer, for: offerUri)
		let credentialInfo = try getCredentialOfferedModels(credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported.filter { offer.credentialConfigurationIdentifiers.contains($0.key) }, batchCredentialIssuance: offer.credentialIssuerMetadata.batchCredentialIssuance)
		let issuerName = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getName(uiCulture) ?? offer.credentialIssuerIdentifier.url.host ?? offer.credentialIssuerIdentifier.url.absoluteString
		let issuerLogoUrl = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getLogo(uiCulture)?.uri?.absoluteString
		return OfferedIssuanceModel(issuerName: issuerName, issuerLogoUrl: issuerLogoUrl, docModels: credentialInfo.map(\.offered), txCodeSpec:  code?.txCode)
	}

	func resolveCredentialOptions(batchCredentialIssuance: BatchCredentialIssuance?, credentialReusePolicy: CredentialReusePolicy? = nil, userCredentialOptions: CredentialOptions? = nil) throws -> CredentialOptions {
		let selectedPolicy = try CredentialReusePolicyValidator.selectMatchingPolicy(
			issuerPolicy: credentialReusePolicy,
			walletSupported: OpenId4VciConfiguration.supportedCredentialReusePolicies
		)
		var issuerSpecifiedBatchSize = CredentialReusePolicyValidator.determineBatchSize(
			selectedPolicy: selectedPolicy,
			issuerBatchSize: batchCredentialIssuance?.batchSize
		) ?? 1
		// Limited-time dictates that a single instance of the attestation is issued that can be used for a limited period.
		if let selectedPolicy, selectedPolicy.method == .limitedTime { issuerSpecifiedBatchSize = 1 }
		try Self.validateBatchSize(issuerSpecifiedBatchSize)
		let reissueTriggerUnused: Int?
		let reissueTriggerLifetimeLeft: Int?
		switch selectedPolicy {
		case .onceOnly(_, let triggerUnused):
			reissueTriggerUnused = triggerUnused
			reissueTriggerLifetimeLeft = nil
		case .limitedTime(let triggerLifetimeLeft):
			reissueTriggerUnused = nil
			reissueTriggerLifetimeLeft = triggerLifetimeLeft
		case .rotatingBatch(_, let triggerLifetimeLeft):
			reissueTriggerUnused = nil
			reissueTriggerLifetimeLeft = triggerLifetimeLeft
		case .perRelyingParty(_, let triggerUnused, let triggerLifetimeLeft):
			reissueTriggerUnused = triggerUnused
			reissueTriggerLifetimeLeft = triggerLifetimeLeft
		case nil:
			reissueTriggerUnused = nil
			reissueTriggerLifetimeLeft = nil
		}
		let resolvedPolicy: CredentialPolicy = if case .onceOnly = selectedPolicy { .oneTimeUse } else { .rotateUse }
		var resolved = userCredentialOptions ?? CredentialOptions(
			credentialPolicy: resolvedPolicy,
			batchSize: issuerSpecifiedBatchSize,
			reissueTriggerUnused: reissueTriggerUnused,
			reissueTriggerLifetimeLeft: reissueTriggerLifetimeLeft
		)
		if resolved.batchSize > issuerSpecifiedBatchSize {
			logger.warning("Credential options batch size \(resolved.batchSize) is larger than the default batch size \(issuerSpecifiedBatchSize). Using the default batch size.")
			resolved.batchSize = issuerSpecifiedBatchSize
		}
		if credentialReusePolicy != nil {
			// Issuer-defined reuse policy takes precedence over user-provided policy fields.
			resolved.credentialPolicy = resolvedPolicy
			resolved.batchSize = issuerSpecifiedBatchSize
			resolved.reissueTriggerUnused = reissueTriggerUnused
			resolved.reissueTriggerLifetimeLeft = reissueTriggerLifetimeLeft
		}
		try Self.validateBatchSize(resolved.batchSize)
		return resolved
	}

	func getIssuerReusePolicy(_ docTypeIdentifier: DocTypeIdentifier, credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported]) -> CredentialReusePolicy? {
		let matchingCredential = credentialsSupported.first {
			switch $0.value {
			case .msoMdoc(let msoMdoc):
				return if let identifier = docTypeIdentifier.configurationIdentifier { $0.key.value == identifier }
				else if let docType = docTypeIdentifier.docType { msoMdoc.docType == docType }
				else { false }
			case .sdJwtVc(let sdJwtVc):
				return if let identifier = docTypeIdentifier.configurationIdentifier { $0.key.value == identifier }
				else if let vct = docTypeIdentifier.vct { sdJwtVc.vct == vct }
				else { false }
			default:
				return false
			}
		}?.value
		return switch matchingCredential {
		case .msoMdoc(let msoMdoc): msoMdoc.credentialMetadata?.credentialReusePolicy
		case .sdJwtVc(let sdJwtVc): sdJwtVc.credentialMetadata?.credentialReusePolicy
		default: nil
		}
	}

	func getMetadataDefaultCredentialOptions(_ docTypeIdentifier: DocTypeIdentifier, offerMetadata: CredentialIssuerMetadata? = nil, userCredentialOptions: CredentialOptions? = nil) async throws -> CredentialOptions {
		let metaData: CredentialIssuerMetadata = if let offerMetadata { offerMetadata } else { try await getIssuerMetadata() }
		let issuerReusePolicy = getIssuerReusePolicy(docTypeIdentifier, credentialsSupported: metaData.credentialsSupported)
		return try resolveCredentialOptions(batchCredentialIssuance: metaData.batchCredentialIssuance, credentialReusePolicy: issuerReusePolicy, userCredentialOptions: userCredentialOptions)
	}

	func getIssuer(offer: CredentialOffer, dpopKeyId: String? = nil) async throws -> Issuer {
		var dpopConstructor: DPoPConstructorType? = nil
		if config.requireDpop {
			dpopConstructor = try await config.makePoPConstructor(popUsage: .dpop, privateKeyId: dpopKeyId ?? issueReq.dpopKeyId, algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported, keyOptions: config.dpopKeyOptions)
		}
		let vciConfig = try await config.toOpenId4VCIConfig(credentialIssuerId: offer.credentialIssuerIdentifier.url.absoluteString, clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported)
		return try Issuer(authorizationServerMetadata: offer.authorizationServerMetadata, issuerMetadata: offer.credentialIssuerMetadata, config: vciConfig, parPoster: Poster(session: networking), tokenPoster: Poster(session: networking), requesterPoster: Poster(session: networking), deferredRequesterPoster: Poster(session: networking), notificationPoster: Poster(session: networking), noncePoster: Poster(session: networking), dpopConstructor: dpopConstructor)
	}

	public func getIssuerMetadata() async throws -> CredentialIssuerMetadata {
		let (_, metadata) = try await resolveIssuerMetadata()
		return metadata
	}

	func getIssuerForDeferred(data: DeferredIssuanceModel, configuration: CredentialConfiguration, dpopKeyId: String? = nil) async throws -> (Issuer,DPoPConstructor?) {
		let vciConfig = try await config.toOpenId4VCIConfig(credentialIssuerId: configuration.credentialIssuerIdentifier, clientAttestationPopSigningAlgValuesSupported: configuration.clientAttestationPopSigningAlgValuesSupported?.map { JWSAlgorithm(name: $0) })
		var dpopConstructor: DPoPConstructor? = nil
		let dpopSigningAlgValuesSupported = configuration.dpopSigningAlgValuesSupported?.map { JWSAlgorithm(name: $0) }
		if config.requireDpop {
			dpopConstructor = try await config.makePoPConstructor(popUsage: .dpop, privateKeyId: dpopKeyId ?? issueReq.dpopKeyId, algorithms: dpopSigningAlgValuesSupported, keyOptions: config.dpopKeyOptions)
		}
		let (_, issuerMetadata) = try await resolveIssuerMetadata()
		guard let authorizationServer = issuerMetadata.authorizationServers?.first else {
			throw PresentationSession.makeError(str: "Invalid authorization server - no authorization server found")
		}
		let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking), oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()
		let issuer = try Issuer(authorizationServerMetadata: authorizationServerMetadata, issuerMetadata: .init(deferredCredentialEndpoint: data.deferredCredentialEndpoint), config: vciConfig, dpopConstructor: dpopConstructor, session: networking)
		return (issuer, dpopConstructor)
	}

	func authorizeOffer(offer: CredentialOffer, docTypeModels: [OfferedDocModel], txCodeValue: String?, authorized: AuthorizedRequest?, forceRefreshToken: Bool, backgroundOnly: Bool = false, dpopKeyId: String? = nil) async throws -> (AuthorizeRequestOutcome, Issuer, [CredentialConfiguration]) {
		try validateConfiguredIssuer(offer.credentialIssuerIdentifier.url.absoluteString)
		let credentialConfigurations = docTypeModels.compactMap { try? getCredentialConfiguration(credentialIssuerIdentifier: offer.credentialIssuerIdentifier.url.absoluteString, issuerDisplay: offer.credentialIssuerMetadata.display, credentialsSupported: offer.credentialIssuerMetadata.credentialsSupported, identifier: $0.credentialConfigurationIdentifier, docType: $0.docType, vct: $0.vct, batchCredentialIssuance: offer.credentialIssuerMetadata.batchCredentialIssuance, dpopSigningAlgValuesSupported: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name), clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name)) }
		guard credentialConfigurations.count > 0, credentialConfigurations.count == docTypeModels.count else {
			throw PresentationSession.makeError(str: "Missing Credential identifiers - expected: \(docTypeModels.count), found: \(credentialConfigurations.count)")
		}
		let code: Grants.PreAuthorizedCode? = switch offer.grants {	case .preAuthorizedCode(let preAuthorizedCode): preAuthorizedCode; case .both(_, let preAuthorizedCode): preAuthorizedCode; case .authorizationCode(_), .none: nil	}
		let txCodeSpec: TxCode? = code?.txCode
		let preAuthorizedCode: String? = code?.preAuthorizedCode
		let issuer = try await getIssuer(offer: offer, dpopKeyId: dpopKeyId)
		if preAuthorizedCode != nil && txCodeSpec != nil && txCodeValue == nil {
			throw PresentationSession.makeError(str: "A transaction code is required for this offer")
		}
		let authorizedOutcome: AuthorizeRequestOutcome
		if var authorized {
			do {
				logger.info("Access token issued at: \(Date(timeIntervalSinceReferenceDate:authorized.timeStamp)), now: \(Date()), expires at \(Date(timeIntervalSinceReferenceDate:authorized.timeStamp + (authorized.accessToken.expiresIn ?? 0)))")
				authorized = try await refreshAuthorization(issuer: issuer, authorized: authorized,	configuration: credentialConfigurations[0], forceRefreshToken: forceRefreshToken)
				authorizedOutcome = .authorized(authorized)
				return (authorizedOutcome, issuer, credentialConfigurations)
			}
			catch CredentialIssuanceError.requestFailed(let code, let error, let description) where !backgroundOnly && forceRefreshToken && (400..<500).contains(code) {
				logger.error("Refresh token authentication failure with status code: \(code), error: \(error) \(description ?? "").")
			}
		}
		if let preAuthorizedCode, let authCode = try? IssuanceAuthorization(preAuthorizationCode: preAuthorizedCode, txCode: txCodeSpec) {
			let vciConfig = try await config.toOpenId4VCIConfig(credentialIssuerId: offer.credentialIssuerIdentifier.url.absoluteString, clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported)
			let authorized = try await issuer.authorizeWithPreAuthorizationCode(credentialOffer: offer, authorizationCode: authCode, client: vciConfig.client, transactionCode: txCodeValue)
			authorizedOutcome = .authorized(authorized)
		} else if !backgroundOnly {
			authorizedOutcome = try await authorizeRequestWithAuthCodeUseCase(issuer: issuer, offer: offer)
		} else {
			throw PresentationSession.makeError(str: "Offer requires user interaction for authorization, but backgroundOnly is set to true, forced refresh token is \(forceRefreshToken).")
		}
		return (authorizedOutcome, issuer, credentialConfigurations)
	}

	func issueDocumentByOfferUrl(issuer: Issuer, offer: CredentialOffer, authorizedOutcome: AuthorizeRequestOutcome, configuration: CredentialConfiguration, bindingKeys: [BindingKey], publicKeys: [Data], promptMessage: String? = nil) async throws -> IssuanceOutcome {
		if case .presentation_request(let url) = authorizedOutcome, let authRequested {
			logger.info("Dynamic issuance requires a presentation request")
			let uuid = UUID().uuidString
			cache.store(offer, for: uuid)
			return .pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url.absoluteString), configuration: configuration, metadataKey: uuid, offerRequestJSON: try Self.makeCredentialOfferRequestJSON(offer), pckeCodeVerifier: authRequested.pkceVerifier.codeVerifier, pckeCodeVerifierMethod: authRequested.pkceVerifier.codeVerifierMethod, state: authRequested.state ))
		}
		guard case .authorized(let authorized) = authorizedOutcome else {
			throw PresentationSession.makeError(str: "Invalid authorized request outcome")
		}
		let id = configuration.configurationIdentifier.value; let sc = configuration.scope; let dn = configuration.display.getName(uiCulture) ?? ""
		logger.info("Starting issuing with identifer \(id), scope \(sc ?? ""), displayName: \(dn)")
		let res = try await Self.submissionUseCase(authorized, issuer: issuer, configuration: configuration, bindingKeys: bindingKeys, publicKeys: publicKeys, logger: logger)
		return res
	}

	static func makeMetadataResolver(_ networking: any Networking) -> CredentialIssuerMetadataResolver {
	 CredentialIssuerMetadataResolver(fetcher: MetadataFetcher(rawFetcher: RawDataFetcher(session: networking), processor: MetadataProcessor()))
	}

	/// Encode only the offer request inputs. Resolved metadata intentionally is
	/// not persisted so resumption re-applies the current service trust policy.
	static func makeCredentialOfferRequestJSON(_ offer: CredentialOffer) throws -> String {
		var object: [String: Any] = [
			"credential_issuer": offer.credentialIssuerIdentifier.url.absoluteString,
			"credential_configuration_ids": offer.credentialConfigurationIdentifiers.map(\.value)
		]
		if let grants = offer.grants {
			func authorizationCodeObject(_ value: Grants.AuthorizationCode) -> [String: Any] {
				var result: [String: Any] = [:]
				if let issuerState = value.issuerState { result["issuer_state"] = issuerState }
				if let server = value.authorizationServer { result["authorization_server"] = server.absoluteString }
				return result
			}
			func preAuthorizedCodeObject(_ value: Grants.PreAuthorizedCode) throws -> [String: Any] {
				var result: [String: Any] = [:]
				if let code = value.preAuthorizedCode { result["pre-authorized_code"] = code }
				if let txCode = value.txCode {
					result["tx_code"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(txCode))
				}
				if let server = value.authorizationServer { result["authorization_server"] = server.absoluteString }
				return result
			}

			var grantObject: [String: Any] = [:]
			switch grants {
			case .authorizationCode(let authorizationCode):
				grantObject["authorization_code"] = authorizationCodeObject(authorizationCode)
			case .preAuthorizedCode(let preAuthorizedCode):
				grantObject["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = try preAuthorizedCodeObject(preAuthorizedCode)
			case .both(let authorizationCode, let preAuthorizedCode):
				grantObject["authorization_code"] = authorizationCodeObject(authorizationCode)
				grantObject["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = try preAuthorizedCodeObject(preAuthorizedCode)
			}
			object["grants"] = grantObject
		}
		let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
		guard let json = String(data: data, encoding: .utf8) else {
			throw PresentationSession.makeError(str: "Unable to persist credential offer")
		}
		return json
	}

	func resolvePersistedCredentialOffer(_ json: String) async throws -> CredentialOffer {
		guard let requestObject = CredentialOfferRequestObject(jsonString: json),
			let issuerURL = URL(string: requestObject.credentialIssuer) else {
			throw PresentationSession.makeError(str: "Persisted credential offer is invalid")
		}
		try validateConfiguredIssuer(requestObject.credentialIssuer)
		try EudiWallet.validateHTTPSRemoteURL(issuerURL, purpose: "Credential issuer")
		let resolver = CredentialOfferRequestResolver(
			fetcher: Fetcher<CredentialOfferRequestObject>(session: networking),
			credentialIssuerMetadataResolver: Self.makeMetadataResolver(networking),
			authorizationServerMetadataResolver: AuthorizationServerMetadataResolver(
				oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking),
				oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)
			)
		)
		let result = await resolver.resolve(source: .passByValue(metaData: json), policy: config.issuerMetadataPolicy)
		do { return try result.get() }
		catch { throw PresentationSession.makeError(str: "Unable to restore credential offer: \(error.localizedDescription)") }
	}

	func resolveIssuerMetadata() async throws -> (CredentialIssuerId, CredentialIssuerMetadata) {
		guard let issuerURL = config.credentialIssuerURL else {
			throw PresentationSession.makeError(str: "credentialIssuerURL must be set in OpenId4VciConfiguration")
		}
		if config.cacheIssuerMetadata, let cachedIssuerMetadata, cachedIssuerMetadata.url == issuerURL {
			return cachedIssuerMetadata.value
		}
		let credentialIssuerIdentifier = try CredentialIssuerId(issuerURL)
		let issuerMetadata = try await Self.makeMetadataResolver(networking).resolve(source: .credentialIssuer(credentialIssuerIdentifier), policy: config.issuerMetadataPolicy)
		switch issuerMetadata {
		case .success(let metaData):
			let result = (credentialIssuerIdentifier, metaData)
			if config.cacheIssuerMetadata { cachedIssuerMetadata = (issuerURL, result) }
			return result
		case .failure(let error):
			throw PresentationSession.makeError(str: "Failed to resolve issuer metadata: \(error.localizedDescription)")
		}
	}

	func validateCredentialOptions(docTypeIdentifier: DocTypeIdentifier, credentialOptions: CredentialOptions?, offer: CredentialOffer? = nil) async throws -> CredentialOptions {
		return try await getMetadataDefaultCredentialOptions(docTypeIdentifier, offerMetadata: offer?.credentialIssuerMetadata, userCredentialOptions: credentialOptions)
	}

	/// Reissue a document by loading its metadata from storage and resolving the credential configuration from the issuer
	///
	/// If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document"
	/// - Parameters:
	///   - documentId: The ID of the document to reissue
	///   - credentialOptions: Credential options specifying batch size and credential policy. If nil, defaults from the configuration are used.
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: Array of issued documents. They are saved in storage.
	@discardableResult func reissueDocument(documentId: WalletStorage.Document.ID, docMetadata: DocMetadata, authorized: AuthorizedRequest? = nil, credentialOptions: CredentialOptions? = nil, keyOptions: KeyOptions? = nil, promptMessage: String? = nil, backgroundOnly: Bool = false) async throws -> [WalletStorage.Document] {
		let (credentialConfigurations, offer) = try await buildCredentialOffer(for: [.identifier(docMetadata.configurationIdentifier)])
		guard let credentialConfiguration = credentialConfigurations.first else {
			throw PresentationSession.makeError(str: "Issuer returned no credential configuration for reissuance")
		}
		let offerUri = UUID().uuidString
		let docTypes = [makeOfferedDocModel(from: credentialConfiguration, credentialOptions: credentialOptions, keyOptions: keyOptions)]
		let reissueAction: (Bool) async throws -> [WalletStorage.Document] = { forceRefreshToken in
			return try await self.issueDocumentsByOfferUrl(offerUri: offerUri, resolvedOffer: offer, docTypes: docTypes, authorized: authorized, forceRefreshToken: forceRefreshToken, documentId: documentId, txCodeValue: nil, promptMessage: promptMessage, backgroundOnly: backgroundOnly, dpopKeyId: docMetadata.dpopKeyId)
		}
		do {
			return try await reissueAction(false)
		} catch CredentialIssuanceError.requestFailed(let code, let error, let description) where (400..<500).contains(code) {
				logger.error("Authentication failure with status code: \(code), error: \(error) \(description ?? "").")
			return try await reissueAction(true)
		}
		catch PostError.requestError(let code, let error) where (400..<500).contains(code) {
				logger.error("Authentication failure with status code: \(code), error: \(error).")
			return try await reissueAction(true)
		}
	}

	/// Issue multiple documents using OpenId4Vci protocol
	///
	/// If ``userAuthenticationRequired`` is true, user authentication is required. The authentication prompt message has localisation key "issue_document"
	/// - Parameters:
	///   - docTypeIdentifiers: Array of document type identifiers (msoMdoc, sdJwt, or configuration identifier)
	///   - credentialOptions: Credential options specifying batch size and credential policy. If nil, defaults are fetched from issuer metadata.
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	///   - promptMessage: Prompt message for biometric authentication (optional)
	/// - Returns: Array of issued documents. They are saved in storage.
	@discardableResult public func issueDocuments(docTypeIdentifiers: [DocTypeIdentifier], credentialOptions: CredentialOptions? = nil, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {
		if docTypeIdentifiers.isEmpty { return [] }
		let (credentialConfigurations, offer) = try await buildCredentialOffer(for: docTypeIdentifiers)
		let offerUri = UUID().uuidString
		// Build OfferedDocModel array from configurations
		let docTypes: [OfferedDocModel] = credentialConfigurations.map {
			makeOfferedDocModel(from: $0, credentialOptions: credentialOptions, keyOptions: keyOptions)
		}
		// Delegate to issueDocumentsByOfferUrl
		return try await issueDocumentsByOfferUrl(offerUri: offerUri, resolvedOffer: offer, docTypes: docTypes, authorized: nil, documentId: nil,  txCodeValue: nil, promptMessage: promptMessage)
	}

	/// Issue documents by offer URI.
	/// - Parameters:
	///   - offerUri: url with offer
	///   - docTypes: offered doc models available to be issued. Contains key options (secure are name and other options)
	///   - txCodeValue: Transaction code given to user (if available)
	///   - promptMessage: prompt message for biometric authentication (optional)
	/// - Returns: Array of issued and stored documents
	func issueDocumentsByOfferUrl(offerUri: String, resolvedOffer: CredentialOffer? = nil, docTypes: [OfferedDocModel], authorized: AuthorizedRequest?, forceRefreshToken: Bool = false, documentId: String?, txCodeValue: String? = nil, promptMessage: String? = nil, backgroundOnly: Bool = false, dpopKeyId: String? = nil) async throws -> [WalletStorage.Document] {
		let operationToken = try beginExclusiveIssuanceOperation()
		defer { endExclusiveIssuanceOperation(operationToken) }
		if docTypes.isEmpty { return [] }
		guard docTypes.allSatisfy({ $0.docTypeIdentifier != nil }) else {
			throw PresentationSession.makeError(str: "Every offered document must contain a credential identifier, docType, or vct")
		}
		guard let offer = resolvedOffer ?? cache.takeCredentialOffer(for: offerUri) else {
			throw PresentationSession.makeError(str: "Offer URI not resolved: \(offerUri)")
		}
		var openId4VCIServices = [OpenId4VciService]()
		for (i, docTypeModel) in docTypes.enumerated() {
			let docTypeIdentifier = docTypeModel.docTypeIdentifier!
			let svc = try OpenId4VciService(uiCulture: uiCulture, config: config, networking: networking, storage: storage, storageService: storageService, transactionLogger: transactionLogger, cache: cache)
			if documentId != nil { logger.info("Resolving offer to replace an existing credential") }
			let id = UUID().uuidString //(i == 0 ? documentId : nil) ?? UUID().uuidString
			try await svc.prepareIssuing(id: id, docTypeIdentifier: docTypeIdentifier, displayName: i > 0 ? nil : docTypes.map(\.displayName).joined(separator: ", "), credentialOptions: docTypeModel.credentialOptions, keyOptions: docTypeModel.keyOptions, disablePrompt: i > 0, promptMessage: promptMessage, offer: offer)
			openId4VCIServices.append(svc)
		}
		guard let authorizationService = openId4VCIServices.first else {
			throw PresentationSession.makeError(str: "No valid credential configuration was selected")
		}
		let (auth, issuer, credentialInfos) = try await authorizationService.authorizeOffer(offer: offer, docTypeModels: docTypes, txCodeValue: txCodeValue, authorized: authorized, forceRefreshToken: forceRefreshToken, backgroundOnly: backgroundOnly, dpopKeyId: dpopKeyId)
		let proofSubject = await issuer.config.client.id
		let issuerName = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getName(uiCulture) ?? offer.credentialIssuerIdentifier.url.host ?? offer.credentialIssuerIdentifier.url.absoluteString
		let issuerIdentifier = offer.credentialIssuerIdentifier.url.absoluteString
		let issuerLogoUrl = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getLogo(uiCulture)?.uri?.absoluteString
		let documents = try await withThrowingTaskGroup(of: IndexedIssuedDocument.self) { group in
			for (i, openId4VCIService) in openId4VCIServices.enumerated() {
				group.addTask {
						do {
							let (bindingKeys, publicKeys): ([BindingKey], [Data])
							if case .presentation_request = auth {
								// Dynamic issuance is not authorized yet. Create credential
								// keys only when the flow resumes successfully.
								(bindingKeys, publicKeys) = ([], [])
							} else {
								(bindingKeys, publicKeys) = try await openId4VCIService.initSecurityKeys(credentialInfos[i], proofSubject: proofSubject)
							}
						let docData = try await openId4VCIService.issueDocumentByOfferUrl(issuer: issuer, offer: offer, authorizedOutcome: auth, configuration: credentialInfos[i], bindingKeys: bindingKeys, publicKeys: publicKeys, promptMessage: promptMessage)
						let document = try await openId4VCIService.finalizeIssuing(issueOutcome: docData, docType: docTypes[i].docTypeOrVct, format: credentialInfos[i].format, issueReq: openId4VCIService.issueReq, deleteId: documentId, issuer: issuer, dpopKeyId: dpopKeyId, issuerName: issuerName, issuerIdentifier: issuerIdentifier, issuerLogoUrl: issuerLogoUrl)
						return IndexedIssuedDocument(index: i, document: document)
					} catch {
						await openId4VCIService.cleanupIssueRequestKeys()
						throw error
					}
				}
			}
			var result = [IndexedIssuedDocument]()
			for try await doc in group { result.append(doc) }
			return result.sorted { $0.index < $1.index }.map(\.document)
		}
		return documents
	}

	func getCredentialConfiguration(credentialIssuerIdentifier: String, issuerDisplay: [Display], credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], identifier: String?, docType: String?, vct: String?, batchCredentialIssuance: BatchCredentialIssuance?, dpopSigningAlgValuesSupported: [String]?, clientAttestationPopSigningAlgValuesSupported: [String]?) throws -> CredentialConfiguration {
			if let credential = credentialsSupported.first(where: { if case .msoMdoc(let msoMdocCred) = $0.value, docType != nil || identifier != nil, msoMdocCred.docType == docType || docType == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .msoMdoc(msoMdocConf) = credential.value {
			logger.info("msoMdoc with scope \(String(describing: msoMdocConf.scope)), cryptographic suites: \(msoMdocConf.credentialSigningAlgValuesSupported)")
			let proofTypesSupported = msoMdocConf.proofTypesSupported ?? [:]
			let (jwtProofType, _, _, supportsAttestationProofType, supportsJwtProofTypeWithoutAttestation, supportsJwtProofTypeWithAttestation) = resolveProofTypeAttestationSupport(proofTypesSupported: proofTypesSupported)
			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: msoMdocConf.docType, vct: nil, scope: msoMdocConf.scope, supportsAttestationProofType: supportsAttestationProofType, supportsJwtProofTypeWithAttestation: supportsJwtProofTypeWithAttestation, supportsJwtProofTypeWithoutAttestation: supportsJwtProofTypeWithoutAttestation, credentialSigningAlgValuesSupported: jwtProofType?.algorithms ?? [], dpopSigningAlgValuesSupported: dpopSigningAlgValuesSupported, clientAttestationPopSigningAlgValuesSupported: clientAttestationPopSigningAlgValuesSupported, issuerDisplay: issuerDisplay.map(\.displayMetadata), display: msoMdocConf.credentialMetadata?.display.map(\.displayMetadata) ?? [], claims: msoMdocConf.credentialMetadata?.claims ?? [], credentialMetadata: msoMdocConf.credentialMetadata, format: .cbor, defaultCredentialOptions: try resolveCredentialOptions(batchCredentialIssuance: batchCredentialIssuance, credentialReusePolicy: msoMdocConf.credentialMetadata?.credentialReusePolicy))
		} else if let credential =  credentialsSupported.first(where: { if case .sdJwtVc(let sdJwtVc) = $0.value, vct != nil || identifier != nil, sdJwtVc.vct == vct || vct == nil, $0.key.value == identifier || identifier == nil { true } else { false } }), case let .sdJwtVc(sdJwtVc) = credential.value {
			logger.info("sdJwtVc with vct \(sdJwtVc.vct ?? ""), identifier: \(credential.key.value), cryptographic suites: \(sdJwtVc.credentialSigningAlgValuesSupported)")
			let proofTypesSupported = sdJwtVc.proofTypesSupported ?? [:]
			let (jwtProofType, _, _, supportsAttestationProofType, supportsJwtProofTypeWithoutAttestation, supportsJwtProofTypeWithAttestation) = resolveProofTypeAttestationSupport(proofTypesSupported: proofTypesSupported)
			return CredentialConfiguration(configurationIdentifier: credential.key, credentialIssuerIdentifier: credentialIssuerIdentifier, docType: nil, vct: sdJwtVc.vct, scope: sdJwtVc.scope,  supportsAttestationProofType: supportsAttestationProofType, supportsJwtProofTypeWithAttestation: supportsJwtProofTypeWithAttestation,  supportsJwtProofTypeWithoutAttestation: supportsJwtProofTypeWithoutAttestation, credentialSigningAlgValuesSupported: jwtProofType?.algorithms ?? [], dpopSigningAlgValuesSupported: dpopSigningAlgValuesSupported, clientAttestationPopSigningAlgValuesSupported: clientAttestationPopSigningAlgValuesSupported, issuerDisplay: issuerDisplay.map(\.displayMetadata), display: sdJwtVc.credentialMetadata?.display.map(\.displayMetadata) ?? [], claims: sdJwtVc.credentialMetadata?.claims ?? [], credentialMetadata: sdJwtVc.credentialMetadata, format: .sdjwt, defaultCredentialOptions: try resolveCredentialOptions(batchCredentialIssuance: batchCredentialIssuance, credentialReusePolicy: sdJwtVc.credentialMetadata?.credentialReusePolicy))
		}
		let requestedParams = [docType.map { "docType: \($0)" }, vct.map { "vct: \($0)" }, identifier.map { "identifier: \($0)" }].compactMap { $0 }.joined(separator: ", ")
		logger.error("No credential configuration found with \(requestedParams). Available credential identifiers: \(credentialsSupported.keys.map(\.value).joined(separator: ", "))")
		throw PresentationSession.makeError(str: "Issuer does not support the requested credential with \(requestedParams).")
	}

	func buildCredentialOffer(for docTypeIdentifiers: [DocTypeIdentifier]) async throws -> ([CredentialConfiguration], CredentialOffer) {
		let (credentialIssuerIdentifier, metaData) = try await resolveIssuerMetadata()
		guard let authorizationServer = metaData.authorizationServers?.first else {
			throw PresentationSession.makeError(str: "Invalid authorization server - no authorization server found")
		}
		let authServerMetadata = await AuthorizationServerMetadataResolver(oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking), oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()
		var credentialConfigurations: [CredentialConfiguration] = []
		var configurationIdentifiers: [CredentialConfigurationIdentifier] = []
		for docTypeIdentifier in docTypeIdentifiers {
			let configuration = try buildCredentialConfiguration(
				docTypeIdentifier: docTypeIdentifier,
				credentialIssuerIdentifier: credentialIssuerIdentifier,
				metaData: metaData,
				authorizationServerMetadata: authorizationServerMetadata
			)
			credentialConfigurations.append(configuration)
			configurationIdentifiers.append(configuration.configurationIdentifier)
		}
		let offer = try CredentialOffer(
			credentialIssuerIdentifier: credentialIssuerIdentifier,
			credentialIssuerMetadata: metaData,
			credentialConfigurationIdentifiers: configurationIdentifiers,
			grants: nil,
			authorizationServerMetadata: authorizationServerMetadata
		)
		return (credentialConfigurations, offer)
	}

	func buildCredentialConfiguration(docTypeIdentifier: DocTypeIdentifier, credentialIssuerIdentifier: CredentialIssuerId, metaData: CredentialIssuerMetadata, authorizationServerMetadata: IdentityAndAccessManagementMetadata) throws -> CredentialConfiguration {
		try getCredentialConfiguration(credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString, issuerDisplay: metaData.display, credentialsSupported: metaData.credentialsSupported, identifier: docTypeIdentifier.configurationIdentifier, docType: docTypeIdentifier.docType, vct: docTypeIdentifier.vct, batchCredentialIssuance: metaData.batchCredentialIssuance, dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name), clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name))
	}

	func makeOfferedDocModel(from config: CredentialConfiguration, credentialOptions: CredentialOptions?, keyOptions: KeyOptions?) -> OfferedDocModel {
		OfferedDocModel(credentialConfigurationIdentifier: config.configurationIdentifier.value, docType: config.docType, vct: config.vct, scope: config.scope ?? "", identifier: config.configurationIdentifier.value, displayName: config.display.getName(uiCulture) ?? config.docType ?? config.vct ?? config.scope ?? "", algValuesSupported: config.credentialSigningAlgValuesSupported, claims: config.claims, credentialMetadata: config.credentialMetadata, credentialOptions: credentialOptions ?? config.defaultCredentialOptions, keyOptions: keyOptions)
	}

	func getCredentialOfferedModels(credentialsSupported: [CredentialConfigurationIdentifier: CredentialSupported], batchCredentialIssuance: BatchCredentialIssuance?) throws -> [(identifier: CredentialConfigurationIdentifier, scope: String?, offered: OfferedDocModel)] {
		var credentialInfos: [(identifier: CredentialConfigurationIdentifier, scope: String?, offered: OfferedDocModel)] = []
		for credential in credentialsSupported {
			if case .msoMdoc(let msoMdocCred) = credential.value {
				let dco = try resolveCredentialOptions(batchCredentialIssuance: batchCredentialIssuance, credentialReusePolicy: msoMdocCred.credentialMetadata?.credentialReusePolicy)
				let offered = OfferedDocModel(credentialConfigurationIdentifier: credential.key.value, docType: msoMdocCred.docType, vct: nil, scope: msoMdocCred.scope, identifier: credential.key.value, displayName: msoMdocCred.credentialMetadata?.display.map(\.displayMetadata).getName(uiCulture) ?? msoMdocCred.docType, algValuesSupported: msoMdocCred.credentialSigningAlgValuesSupported, claims: msoMdocCred.credentialMetadata?.claims ?? [], credentialMetadata: msoMdocCred.credentialMetadata, credentialOptions: dco, keyOptions: nil)
				credentialInfos.append((identifier: credential.key, scope: msoMdocCred.scope, offered: offered))
			} else if case .sdJwtVc(let sdJwtVc) = credential.value {
				let dco = try resolveCredentialOptions(batchCredentialIssuance: batchCredentialIssuance, credentialReusePolicy: sdJwtVc.credentialMetadata?.credentialReusePolicy)
				let offered = OfferedDocModel(credentialConfigurationIdentifier: credential.key.value, docType: nil, vct: sdJwtVc.vct, scope: sdJwtVc.scope, identifier: credential.key.value, displayName: sdJwtVc.credentialMetadata?.display.map(\.displayMetadata).getName(uiCulture) ?? "", algValuesSupported: sdJwtVc.credentialSigningAlgValuesSupported, claims: sdJwtVc.credentialMetadata?.claims ?? [], credentialMetadata: sdJwtVc.credentialMetadata, credentialOptions: dco, keyOptions: nil)
				credentialInfos.append((identifier: credential.key, scope: sdJwtVc.scope, offered: offered))
			}
		}
		return credentialInfos
	}

	private func authorizeRequestWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer) async throws -> AuthorizeRequestOutcome {
		let pushedAuthorizationRequestEndpoint = if case let .oidc(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint { endpoint } else if case let .oauth(metaData) = offer.authorizationServerMetadata, let endpoint = metaData.pushedAuthorizationRequestEndpoint { endpoint } else { "" }
		if config.parUsage.required && pushedAuthorizationRequestEndpoint.isEmpty {
			logger.info("PAR not supported, Pushed Authorization Request Endpoint is nil")
		}
		logger.info("--> [AUTHORIZATION] Placing request")
		let parPlaced = try await issuer.prepareAuthorizationRequest(credentialOffer: offer)

		self.authRequested = parPlaced
		logger.info("--> [AUTHORIZATION] Request placed")
		let authResult = try await loginUserAndGetAuthCode(authorizationCodeURL: parPlaced.authorizationCodeURL.url)
		logger.info("--> [AUTHORIZATION] Authorization code retrieved")
		switch authResult {
		case .code(let authorizationCode, let serverState):
			return .authorized(try await handleAuthorizationCode(issuer: issuer, offer: offer, request: parPlaced, authorizationCode: authorizationCode, serverState: serverState))
		case .presentation_request(let url):
			return .presentation_request(url)
		}
	}

	private func handleAuthorizationCode(issuer: Issuer, offer: CredentialOffer, request: AuthorizationRequested, authorizationCode: String, serverState: String?) async throws -> AuthorizedRequest {
		let validatedServerState = try Self.validateAuthorizationState(serverState, expectedState: request.state)
		let typedAuthorizationCode = try AuthorizationCode(value: authorizationCode)
		let authorized = try await issuer.authorizeWithAuthorizationCode(serverState: validatedServerState, request: request, authorizationCode: typedAuthorizationCode, authorizationDetailsInTokenRequest: .doNotInclude, grant: try offer.grants ?? .authorizationCode(try Grants.AuthorizationCode(authorizationServer: nil)))
		logger.info("--> [AUTHORIZATION] Authorization code exchanged")
		_ = authorized.accessToken.isExpired(issued: authorized.timeStamp, at: Date().timeIntervalSinceReferenceDate)
		return authorized
	}

	private static func submissionUseCase(_ authorized: AuthorizedRequest, issuer: Issuer, configuration: CredentialConfiguration, bindingKeys: [BindingKey], publicKeys: [Data], logger: Logger) async throws -> IssuanceOutcome {
		let payload: IssuanceRequestPayload = .configurationBased(credentialConfigurationIdentifier: configuration.configurationIdentifier)
		let requestOutcome = try await issuer.requestCredential(request: authorized, bindingKeys: bindingKeys, requestPayload: payload) { Issuer.createResponseEncryptionSpec($0) }
		switch requestOutcome {
		case .success(let response):
			guard let first = response.credentialResponses.first else {
				throw PresentationSession.makeError(str: "No credential response results available")
			}
			switch first {
			case .deferred(let transactionId, let interval):
				guard response.credentialResponses.count == 1 else {
					throw PresentationSession.makeError(str: "Issuer returned an unsupported mixed or multi-transaction deferred response")
				}
				logger.info("Credential issuance deferred; retry interval is \(interval) seconds")
				let derKeyData: Data? = if let encryptionSpec = await issuer.deferredResponseEncryptionSpec, let key = encryptionSpec.privateKey { try secCall { SecKeyCopyExternalRepresentation(key, $0)} as Data } else { nil }
				guard let deferredCredentialEndpoint = await issuer.issuerMetadata.deferredCredentialEndpoint else {
					throw PresentationSession.makeError(str: "Issuer returned a deferred response without a deferred credential endpoint")
				}
				let deferredModel = DeferredIssuanceModel(deferredCredentialEndpoint: deferredCredentialEndpoint, transactionId: transactionId, publicKeys: publicKeys, derKeyData: derKeyData, timeStamp: authorized.timeStamp)
				return .deferred(deferredModel, configuration, authorized)
			case .issued:
				var credentials: [Credential] = []
				var notificationIds = Set<String>()
				for result in response.credentialResponses {
					guard case .issued(_, let credential, let notificationId, _) = result else {
						throw PresentationSession.makeError(str: "Issuer returned mixed issued and deferred credential results")
					}
					credentials.append(credential)
					if let notificationId { notificationIds.insert(notificationId) }
				}
				guard notificationIds.count <= 1 else {
					throw PresentationSession.makeError(str: "Issuer returned conflicting notification identifiers for one credential request")
				}
				return try await Self.handleCredentialResponse(
					credentials: credentials,
					publicKeys: publicKeys,
					configuration: configuration,
					authorized: authorized,
					notificationId: notificationIds.first,
					logger: logger
				)
			}
		case .invalidProof(let errorDescription):
			throw PresentationSession.makeError(str: "Issuer error: " + (errorDescription ?? "The proof is invalid"))
		case .failed(let error):
			throw PresentationSession.makeError(str: error.localizedDescription)
		}
	}

	private static func handleCredentialResponse(credentials: [Credential], publicKeys: [Data], configuration: CredentialConfiguration, authorized: AuthorizedRequest, notificationId: String?, logger: Logger) async throws -> IssuanceOutcome {
		let pairedCredentials = try pairCredentialPayloads(credentials, format: configuration.format, publicKeys: publicKeys)
		logger.info("Received \(pairedCredentials.count) issued credential(s) in \(configuration.format.rawValue) format")
		return .issued(pairedCredentials, configuration, authorized, notificationId: notificationId)
	}

	static func pairCredentialPayloads(_ credentials: [Credential], format: DocDataFormat, publicKeys: [Data]) throws -> [(Data, Data)] {
		let payloads = try decodeCredentialPayloads(credentials, format: format)
		guard payloads.count == publicKeys.count else {
			throw PresentationSession.makeError(
				str: "Credential response count \(payloads.count) does not match binding key count \(publicKeys.count)"
			)
		}
		return Array(zip(payloads, publicKeys))
	}

	static func decodeCredentialPayloads(_ credentials: [Credential], format: DocDataFormat) throws -> [Data] {
		let compactParser = CompactParser()
		let serializedCredentials: [String] = try credentials.flatMap { credential in
			switch credential {
			case .string(let value):
				return [value]
			case .json(let json):
				let elements: [JSON]
				if json.type == .array {
					elements = json.arrayValue
				} else {
					elements = [json]
				}
				guard !elements.isEmpty else {
					throw PresentationSession.makeError(str: "Credential response contains an empty array")
				}
				return try elements.map { element in
					let candidate = element["credential"].exists() ? element["credential"] : element
					if let value = candidate.string { return value }
					do { return try compactParser.stringFromJwsJsonObject(candidate) }
					catch { throw PresentationSession.makeError(str: "Credential response contains invalid JWS JSON") }
				}
			}
		}
		guard !serializedCredentials.isEmpty else {
			throw PresentationSession.makeError(str: "Credential response is empty")
		}
		return try serializedCredentials.map { serialized in
			switch format {
			case .cbor:
				guard let data = Data(base64URLEncoded: serialized), !data.isEmpty else {
					throw PresentationSession.makeError(str: "Credential response contains invalid Base64URL mdoc data")
				}
				return data
			case .sdjwt:
				guard let data = serialized.data(using: .utf8), !data.isEmpty else {
					throw PresentationSession.makeError(str: "Credential response contains invalid SD-JWT data")
				}
				return data
			}
		}
	}

		/// Request a deferred issuance based on a stored deferred document. On success, the deferred document is replaced with the issued document.
	///
	/// The caller does not need to reload documents, storage manager collections are updated.
	/// - Parameters:
	///   - deferredDoc: A stored document with deferred status
	///   - credentialOptions: Credential options specifying batch size and credential policy for the deferred document
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	/// - Returns: The issued document in case it was approved in the backend and the deferred data are valid, otherwise a deferred status document
	@discardableResult public func requestDeferredIssuance(deferredDoc: WalletStorage.Document, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil) async throws -> WalletStorage.Document {
		guard deferredDoc.status == .deferred else { throw PresentationSession.makeError(str: "Invalid document status for deferred issuance: \(deferredDoc.status)") }
		let operationToken = try beginExclusiveIssuanceOperation()
		defer { endExclusiveIssuanceOperation(operationToken) }
		try beginIssuanceResume(id: deferredDoc.id, status: .deferred)
		defer { endIssuanceResume(id: deferredDoc.id, status: .deferred) }
		let storedDeferredDoc = try await persistedPlaceholder(matching: deferredDoc, status: .deferred)
		guard let metadata = DocMetadata(from: storedDeferredDoc.metadata) else {
			throw PresentationSession.makeError(str: "Deferred issuance document metadata is missing")
		}
		try validateConfiguredIssuer(metadata.credentialIssuerIdentifier)
		let data = try await requestDeferredIssuanceInternal(deferredDoc: storedDeferredDoc, credentialOptions: credentialOptions, keyOptions: keyOptions)
		return try await finalizeIssuing(issueOutcome: data, docType: storedDeferredDoc.docType, format: storedDeferredDoc.docDataFormat, issueReq: issueReq, deleteId: nil)
	}

	func requestDeferredIssuanceInternal(deferredDoc: WalletStorage.Document, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil) async throws -> IssuanceOutcome {
		// These arguments are retained for source compatibility. The stored options
		// are authoritative because they define the already-created key batch.
		_ = credentialOptions
		_ = keyOptions
		let model = try JSONDecoder().decode(DeferredIssuanceModel.self, from: deferredDoc.data)
		guard let docMetadata = DocMetadata(from: deferredDoc.metadata) else {
			throw PresentationSession.makeError(str: "Deferred issuance document metadata is missing")
		}
		let configurationIdentifier = docMetadata.configurationIdentifier
		guard let storedCredentialOptions = docMetadata.credentialOptions else {
			throw PresentationSession.makeError(str: "Deferred issuance credential options are missing")
		}
		guard storedCredentialOptions.batchSize == model.publicKeys.count else {
			throw PresentationSession.makeError(str: "Deferred issuance key count does not match stored credential options")
		}
		issueReq = try IssueRequest(id: deferredDoc.id, credentialOptions: storedCredentialOptions, keyOptions: docMetadata.keyOptions)
		guard let authorizedRequestData = docMetadata.authorizedRequestData,
			  let decodedAuthorized = try? JSONDecoder().decode(AuthorizedRequestData.self, from: authorizedRequestData) else {
			throw PresentationSession.makeError(str: "Deferred issuance authorized request data is missing")
		}
		let authorized = decodedAuthorized.toAuthorizedRequest()
		let dpopKeyId = docMetadata.dpopKeyId
		let (credentialConfigurations, _) = try await buildCredentialOffer(for: [.identifier(configurationIdentifier)])
		guard let configuration = credentialConfigurations.first else {
			throw PresentationSession.makeError(str: "Deferred issuance credential configuration could not be resolved")
		}
		let deferredAction: (Bool) async throws -> IssuanceOutcome = { forceRefreshToken in
			let (issuer, dpopConstructor) = try await self.getIssuerForDeferred(data: model, configuration: configuration, dpopKeyId: dpopKeyId)
			let refreshedAuthorized = try await self.refreshAuthorization(issuer: issuer, authorized: authorized, configuration: configuration, forceRefreshToken: forceRefreshToken)
			return try await self.deferredCredentialUseCase(issuer: issuer, dpopConstructor: dpopConstructor, authorized: refreshedAuthorized, transactionId: model.transactionId, publicKeys: model.publicKeys, derKeyData: model.derKeyData, configuration: configuration)
		}
		do {
			return try await deferredAction(false)
		} catch CredentialIssuanceError.requestFailed(let code, let error, let description) where (400..<500).contains(code) {
			logger.error("Deferred issuance authentication failure with status code: \(code), error: \(error) \(description ?? "").")
			return try await deferredAction(true)
		} catch PostError.requestError(let code, let error) where (400..<500).contains(code) {
			logger.error("Deferred issuance authentication failure with status code: \(code), error: \(error).")
			return try await deferredAction(true)
		}
	}

	func refreshAuthorization(issuer: Issuer, authorized: AuthorizedRequest, configuration: CredentialConfiguration, forceRefreshToken: Bool) async throws -> AuthorizedRequest {
		guard authorized.isAccessTokenExpired() || forceRefreshToken else { return authorized }
		if let refreshTokenExpiresIn = authorized.refreshToken?.expiresIn,
		   authorized.isRefreshTokenExpired(clock: Date.now.timeIntervalSinceReferenceDate) {
			logger.info("Issuance refresh token expired at \(Date(timeIntervalSinceReferenceDate: authorized.timeStamp + refreshTokenExpiresIn)).")
		}
		let vciConfig = try await config.toOpenId4VCIConfig(
			credentialIssuerId: configuration.credentialIssuerIdentifier,
			clientAttestationPopSigningAlgValuesSupported: configuration.clientAttestationPopSigningAlgValuesSupported?.map { JWSAlgorithm(name: $0) }
		)
		let refreshedAuthorized = try await issuer.refresh(client: vciConfig.client, authorizedRequest: authorized, dPopNonce: nil)
		logger.info("Refreshed authorized request for issuance")
		return refreshedAuthorized
	}


	/// Resume pending issuance. Supports dynamic issuance scenario
	///
	/// The caller does not need to reload documents, storage manager collections are updated.
	/// - Parameters:
	///   - pendingDoc: A temporary document with pending status
	///   - webUrl: The authorization URL returned from the presentation service (for dynamic issuance)
	///   - credentialOptions: Credential options specifying batch size and credential policy for the pending document
	///   - keyOptions: Key options (secure area name and other options) for the document issuing (optional)
	/// - Returns: The issued document in case it was approved in the backend and the pendingDoc data are valid, otherwise a pendingDoc status document
	@discardableResult public func resumePendingIssuance(pendingDoc: WalletStorage.Document, webUrl: URL?, credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil) async throws -> WalletStorage.Document {
		guard pendingDoc.status == .pending else { throw PresentationSession.makeError(str: "Invalid document status for pending issuance: \(pendingDoc.status)")}
		let operationToken = try beginExclusiveIssuanceOperation()
		defer { endExclusiveIssuanceOperation(operationToken) }
		try beginIssuanceResume(id: pendingDoc.id, status: .pending)
		defer { endIssuanceResume(id: pendingDoc.id, status: .pending) }
		let storedPendingDoc = try await persistedPlaceholder(matching: pendingDoc, status: .pending)
		let pendingModel = try JSONDecoder().decode(PendingIssuanceModel.self, from: storedPendingDoc.data)
		try validateConfiguredIssuer(pendingModel.configuration.credentialIssuerIdentifier)
		guard let docTypeIdentifier = storedPendingDoc.docTypeIdentifier else {
			throw PresentationSession.makeError(str: "Pending issuance document has no credential identifier")
		}
		let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions)
		try await prepareIssuing(id: storedPendingDoc.id, docTypeIdentifier: docTypeIdentifier, displayName: nil, credentialOptions: usedCredentialOptions, keyOptions: keyOptions, disablePrompt: true, promptMessage: nil)
		do {
			let outcome = try await resumePendingIssuance(pendingDoc: storedPendingDoc, webUrl: webUrl)
			if case .pending = outcome { return storedPendingDoc }
			return try await finalizeIssuing(issueOutcome: outcome, docType: storedPendingDoc.docType, format: storedPendingDoc.docDataFormat, issueReq: issueReq, deleteId: nil)
		} catch {
			await cleanupIssueRequestKeys()
			throw error
		}
	}

	func resumePendingIssuance(pendingDoc: WalletStorage.Document, webUrl: URL?) async throws -> IssuanceOutcome {
		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: pendingDoc.data)
		try validateConfiguredIssuer(model.configuration.credentialIssuerIdentifier)
		guard case .presentation_request_url(_) = model.pendingReason else {
			throw PresentationSession.makeError(str: "Unknown pending reason: \(model.pendingReason)")
		}
		guard let webUrl else {
			throw PresentationSession.makeError(str: "Web URL not specified")
		}
		let asWeb = try await loginUserAndGetAuthCode(authorizationCodeURL: webUrl)
		guard case .code(let authorizationCode, let serverState) = asWeb else {
			throw PresentationSession.makeError(str: "Pending issuance not authorized")
		}
		let offer: CredentialOffer
		if let cachedOffer = cache.credentialOffer(for: model.metadataKey) {
			offer = cachedOffer
		} else if let requestJSON = model.offerRequestJSON {
			offer = try await resolvePersistedCredentialOffer(requestJSON)
		} else {
			throw PresentationSession.makeError(str: "Pending issuance cannot be completed")
		}
		try validateConfiguredIssuer(offer.credentialIssuerIdentifier.url.absoluteString)
		let issuer = try await getIssuer(offer: offer)
		logger.info("Starting issuing with identifer \(model.configuration.configurationIdentifier.value)")
		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)
		// Append client_id if missing from the redirect URL (fixes presentation-during-issuance flow, see #376)
		var authCodeUrlString = webUrl.absoluteString
		if var components = URLComponents(url: webUrl, resolvingAgainstBaseURL: false),
		   !(components.queryItems ?? []).contains(where: { $0.name == AuthorizationCodeURL.PARAM_CLIENT_ID }) {
			var items = components.queryItems ?? []
			items.append(URLQueryItem(name: AuthorizationCodeURL.PARAM_CLIENT_ID, value: await issuer.config.client.id))
			components.queryItems = items
			if let updatedUrl = components.string { authCodeUrlString = updatedUrl }
		}
		let authorizationCodeURL = try AuthorizationCodeURL(urlString: authCodeUrlString)
		let request = AuthorizationRequested(
			credentials: [try .init(value: model.configuration.configurationIdentifier.value)],
			authorizationCodeURL: authorizationCodeURL, pkceVerifier: pkceVerifier, state: model.state,
			configurationIds: [model.configuration.configurationIdentifier]
		)
		let validatedServerState = try Self.validateAuthorizationState(serverState, expectedState: request.state)
		let authorized = try await issuer.authorizeWithAuthorizationCode(
			serverState: validatedServerState, request: request,
			authorizationCode: try AuthorizationCode(value: authorizationCode),
			grant: try offer.grants ?? .authorizationCode(try Grants.AuthorizationCode(authorizationServer: nil))
		)
		let (bindingKeys, publicKeys) = try await initSecurityKeys(model.configuration, proofSubject: await issuer.config.client.id)
		let res = try await Self.submissionUseCase(authorized, issuer: issuer, configuration: model.configuration, bindingKeys: bindingKeys, publicKeys: publicKeys, logger: logger)
		cache.removeCredentialOffer(for: model.metadataKey)
		return res
	}

	private func deferredCredentialUseCase(issuer: Issuer, dpopConstructor: DPoPConstructor?, authorized: AuthorizedRequest, transactionId: TransactionId, publicKeys: [Data], derKeyData: Data?, configuration: CredentialConfiguration) async throws -> IssuanceOutcome {
		logger.info("--> [ISSUANCE] Retrying deferred issuance")
		var deferredResponseEncryptionSpec: IssuanceResponseEncryptionSpec? = nil
		if let derKeyData {
			deferredResponseEncryptionSpec = await Issuer.createResponseEncryptionSpec(issuer.issuerMetadata.credentialResponseEncryption,  privateKeyData: derKeyData)
			await issuer.setDeferredResponseEncryptionSpec(deferredResponseEncryptionSpec)
		}
		let deferredIssuanceRequester = await IssuanceRequester(issuerMetadata: issuer.issuerMetadata, poster: Poster(session: networking), dpopConstructor: dpopConstructor)
		let deferredRequestResponse = try await deferredIssuanceRequester.placeDeferredCredentialRequest(
			accessToken: authorized.accessToken, transactionId: transactionId, dPopNonce: nil, maxRetries: Constants.MAX_RETRIES, issuanceResponseEncryptionSpec: deferredResponseEncryptionSpec, encryptionSpec: nil)
		switch deferredRequestResponse {
		case .issued(let credential):
			return try await Self.handleCredentialResponse(credentials: [credential], publicKeys: publicKeys, configuration: configuration, authorized: authorized, notificationId: nil, logger: logger)
		case .issuancePending(let transactionId, let interval):
			logger.info("Credential not ready yet. Try after \(interval)")
			guard let deferredCredentialEndpoint = await issuer.issuerMetadata.deferredCredentialEndpoint else {
				throw PresentationSession.makeError(str: "Issuer returned a deferred response without a deferred credential endpoint")
			}
			let deferredModel = DeferredIssuanceModel(deferredCredentialEndpoint: deferredCredentialEndpoint, transactionId: transactionId, publicKeys: publicKeys, derKeyData: derKeyData, timeStamp: authorized.timeStamp)
			return .deferred(deferredModel, configuration, authorized)
		case .issuanceStillPending(let interval):
			logger.info("Credential still not ready. Try again after \(interval)")
			guard let deferredCredentialEndpoint = await issuer.issuerMetadata.deferredCredentialEndpoint else {
				throw PresentationSession.makeError(str: "Issuer returned a deferred response without a deferred credential endpoint")
			}
			let deferredModel = DeferredIssuanceModel(deferredCredentialEndpoint: deferredCredentialEndpoint, transactionId: transactionId, publicKeys: publicKeys, derKeyData: derKeyData, timeStamp: authorized.timeStamp)
			return .deferred(deferredModel, configuration, authorized)
		case .errored(_, let errorDescription):
			throw PresentationSession.makeError(str: "\(errorDescription ?? "Something went wrong with your deferred request response")")
		}
	}

	@MainActor
	private func loginUserAndGetAuthCode(authorizationCodeURL: URL) async throws -> AsWebOutcome {
		try EudiWallet.validateHTTPSRemoteURL(authorizationCodeURL, purpose: "Authorization endpoint")
		#if os(iOS)
		if let scene = UIApplication.shared.connectedScenes.first {
			let activateState = scene.activationState
			if activateState != .foregroundActive { try await Task.sleep(nanoseconds: 1_000_000_000) }
		}
		#endif
		guard let redirectScheme = config.authFlowRedirectionURI.scheme, !redirectScheme.isEmpty else {
			throw PresentationSession.makeError(str: "Authorization redirect URI must include a scheme")
		}
		simpleAuthWebContext = SimpleAuthenticationPresentationContext()
		let lock = NSLock()
		return try await withCheckedThrowingContinuation { continuation in
			var nillableContinuation: CheckedContinuation<AsWebOutcome, Error>? = continuation
			let authenticationSession = ASWebAuthenticationSession(url: authorizationCodeURL, callbackURLScheme: redirectScheme) { url, error in
				Task { @MainActor [weak self] in self?.authenticationSession = nil }
				lock.lock()
				defer { lock.unlock() }
				if let error {
					nillableContinuation?.resume(throwing: WalletError.authRequestFailed(error: error))
					nillableContinuation = nil
					return
				}
				guard let url else {
					nillableContinuation?.resume(throwing: WalletError(description: "Authorization response does not include a url"))
					nillableContinuation = nil
					return
				}
				do {
					let outcome = try Self.classifyAuthenticationCallback(
						url,
						applicationSchemes: Bundle.main.getURLSchemas() ?? []
					)
					self.logger.info(outcome.isAuthorizationCode ? "Authorization code callback received" : "Dynamic issuance callback received")
					nillableContinuation?.resume(returning: outcome)
				} catch {
					nillableContinuation?.resume(throwing: error)
				}
				nillableContinuation = nil
			}
			authenticationSession.presentationContextProvider = simpleAuthWebContext
			self.authenticationSession = authenticationSession
			guard authenticationSession.start() else {
				self.authenticationSession = nil
				nillableContinuation?.resume(throwing: WalletError(description: "Unable to start authorization session"))
				nillableContinuation = nil
				return
			}
		}
	}

	static func classifyAuthenticationCallback(_ url: URL, applicationSchemes: [String]) throws -> AsWebOutcome {
		if let code = url.getQueryStringParameter("code"), !code.isEmpty {
			return .code(code, state: url.getQueryStringParameter("state"))
		}
		if let oauthError = url.getQueryStringParameter("error"), !oauthError.isEmpty {
			throw WalletError(description: "Authorization server returned an OAuth error")
		}
		guard let scheme = url.scheme,
			applicationSchemes.contains(where: { $0.caseInsensitiveCompare(scheme) == .orderedSame }) else {
			throw WalletError(description: "Authorization response does not include a code or supported presentation request")
		}
		return .presentation_request(url)
	}

	final class SimpleAuthenticationPresentationContext: NSObject, ASWebAuthenticationPresentationContextProviding {
		public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
			ASPresentationAnchor()
		}
	}

	/// Find a signing algorithm that is supported by both the secure area and the credential issuer
	private func findCompatibleSigningAlgorithm(algSupported: [JWSAlgorithm.AlgorithmType]) throws -> MdocDataModel18013.SigningAlgorithm {
		// SecureAreaSigner currently supports ECDSA only. Negotiate against the
		// secure area selected for this request, not unrelated global registrations.
		let supportedCurves = type(of: issueReq.secureArea).supportedEcCurves.filter { $0 != .ED25519 }
		let secureAreaSupportedAlgorithms = Set(supportedCurves.map(\.defaultSigningAlgorithm)).sorted { $0.order < $1.order }

		// Check if user has specified a preferred curve in keyOptions
		if let preferredCurve = issueReq.keyOptions?.curve, supportedCurves.contains(preferredCurve) {
			let preferredAlgorithm = preferredCurve.defaultSigningAlgorithm
			let preferredAlgType = Self.mapToJWSAlgorithmType(preferredAlgorithm)
			if let preferredAlgType, algSupported.contains(preferredAlgType) {
				return preferredAlgorithm
			}
		}
		// Otherwise, find the first compatible algorithm from the supported list
		for algorithm in secureAreaSupportedAlgorithms {
			if let algType = Self.mapToJWSAlgorithmType(algorithm), algSupported.contains(algType), let compatibleCurve = Self.getCompatibleCurve(for: algorithm) {
				// Update the issueReq.keyOptions to use the correct curve for this algorithm
				updateKeyOptionsForAlgorithm(algorithm: algorithm, curve: compatibleCurve)
				return algorithm
			}
		}
		throw PresentationSession.makeError(str: "Unable to find supported signing algorithm. Credential issuer supports: \(algSupported.map(\.rawValue)), selected secure area supports: \(secureAreaSupportedAlgorithms.map(\.rawValue))")
	}

	/// Get a compatible curve for the given signing algorithm
	static func getCompatibleCurve(for algorithm: MdocDataModel18013.SigningAlgorithm) -> CoseEcCurve? {
		switch algorithm {
		case .ES256: .P256; case .ES384: .P384; case .ES512: .P521; case .EDDSA: .ED25519
		case .UNSET: nil
		}
	}

	/// Update the issueReq.keyOptions to use the appropriate curve for the selected algorithm
	func updateKeyOptionsForAlgorithm(algorithm: MdocDataModel18013.SigningAlgorithm, curve: CoseEcCurve) {
		if issueReq.keyOptions == nil {
			issueReq.keyOptions = KeyOptions(curve: curve)
		} else if issueReq.keyOptions?.curve == nil || issueReq.keyOptions?.curve != curve {
			// Update the curve to match the selected algorithm
			issueReq.keyOptions?.curve = curve
		}
	}
	/// Map MdocDataModel18013.SigningAlgorithm to JWSAlgorithm.AlgorithmType, handling casing differences
	static func mapToJWSAlgorithmType(_ algorithm: MdocDataModel18013.SigningAlgorithm) -> JWSAlgorithm.AlgorithmType? {
		switch algorithm {
		case .ES256: .ES256; case .ES384: .ES384; case .ES512: .ES512; case .EDDSA: .EdDSA  // Handle the casing difference: EDDSA -> EdDSA
		default: nil
		}
	}

	func finalizeIssuing(issueOutcome: IssuanceOutcome, docType: String?, format: DocDataFormat, issueReq: IssueRequest, deleteId: String?, issuer: (any IssuerType)? = nil, dpopKeyId: String? = nil, issuerName: String? = nil, issuerIdentifier: String? = nil, issuerLogoUrl: String? = nil) async throws -> WalletStorage.Document  {
		var issuedNotificationId: String? = nil
		var issuedAuthorizedRequest: AuthorizedRequest? = nil
		do {
			let savedDpopKeyId = dpopKeyId ?? issueReq.dpopKeyId
			var dataToSave: Data; var docTypeToSave = ""
			var docMetadata: DocMetadata; var displayName: String?
			let pds = issueOutcome.pendingOrDeferredStatus
			var batch: [WalletStorage.Document]?
			var publicKeys: [Data] = []
			var dkInfo = DocKeyInfo(secureAreaName: issueReq.secureAreaName, batchSize: 0, credentialPolicy: issueReq.credentialOptions.credentialPolicy)
			switch issueOutcome {
			case .issued(let dataPairs, let cc, let authorized, let notificationId):
				// Capture for potential failure notification outside switch scope
				issuedNotificationId = notificationId
				issuedAuthorizedRequest = authorized
				guard dataPairs.first != nil else { throw PresentationSession.makeError(str: "Empty issued data array") }
				dataToSave = issueOutcome.getDataToSave(index: 0, format: format)
				docMetadata = cc.convertToDocMetadata(authorized: authorized, keyOptions: issueReq.keyOptions, credentialOptions: issueReq.credentialOptions, dpopKeyId: savedDpopKeyId)
				let docTypeOrVctOrScope = docType ?? cc.docType ?? cc.scope ?? ""
				dkInfo.batchSize = dataPairs.count
				docTypeToSave = if format == .cbor, dataToSave.count > 0 { (try IssuerSigned(data: [UInt8](dataToSave))).issuerAuth.mso.docType } else if format == .sdjwt, dataToSave.count > 0 { SdJwtUtils.getVctFromSdJwt(docData: dataToSave) ?? docTypeOrVctOrScope } else { docTypeOrVctOrScope }
				displayName = cc.display.getName(uiCulture)
				if dataPairs.count > 0 {
					batch = (0..<dataPairs.count).map { WalletStorage.Document(id: issueReq.id, docType: docTypeToSave, docDataFormat: format, data: issueOutcome.getDataToSave(index: $0, format: format), docKeyInfo: nil, createdAt: Date(), metadata: nil, displayName: displayName, status: .issued) }
					publicKeys = dataPairs.map(\.publicKey)
				}
			case .deferred(let deferredIssuanceModel, let cc, let authorized):
				dataToSave = try JSONEncoder().encode(deferredIssuanceModel)
				docMetadata = cc.convertToDocMetadata(authorized: authorized, keyOptions: issueReq.keyOptions, credentialOptions: issueReq.credentialOptions, dpopKeyId: savedDpopKeyId)
				docTypeToSave = docType ?? "DEFERRED"
				displayName = cc.display.getName(uiCulture)
			case .pending(let pendingAuthModel):
				dataToSave = try JSONEncoder().encode(pendingAuthModel)
				docMetadata = pendingAuthModel.configuration.convertToDocMetadata(dpopKeyId: savedDpopKeyId)
				docTypeToSave = docType ?? "PENDING"
				displayName = pendingAuthModel.configuration.display.getName(uiCulture)
			}
			// Download credential display images through the wallet's injected network stack.
			let issuanceNetworking = responseLimitedNetworking
				docMetadata = await docMetadata.downloadingDisplayImages(
					fetch: { try await issuanceNetworking.data(for: $0, maximumResponseBytes: 2 * 1_024 * 1_024) }
			)
			let newDocStatus: WalletStorage.DocumentStatus = issueOutcome.isDeferred ? .deferred : (issueOutcome.isPending ? .pending : .issued)
			let newDocument = WalletStorage.Document(id: issueReq.id, docType: docTypeToSave, docDataFormat: format, data: dataToSave, docKeyInfo: dkInfo.toData(), createdAt: Date(), metadata: docMetadata.toData(), displayName: displayName, status: newDocStatus)
			if newDocStatus == .pending {
				try await endIssueDocument(newDocument, batch: nil)
				await storage.appendDocModel(newDocument, uiCulture: uiCulture)
				await storage.refreshPublishedVars()
				return newDocument
			}
			if newDocStatus == .issued { try await validateIssuedDocuments(newDocument, batch: batch, publicKeys: publicKeys) }
			try await endIssueDocument(newDocument, batch: batch)
			if newDocStatus == .issued, let deleteId, deleteId != newDocument.id {
				do {
					try await storage.deleteDocument(id: deleteId, status: .issued)
				} catch {
					// The replacement has already been committed. Keep both usable
					// credentials instead of reporting failure and deleting its keys.
					logger.warning("Replacement credential was saved, but the previous credential could not be deleted: \(error.localizedDescription)")
				}
			}
			await storage.appendDocModel(newDocument, uiCulture: uiCulture)
			await storage.refreshPublishedVars()
			if newDocStatus == .deferred {
				do {
					try await storage.removePlaceholder(id: issueReq.id, status: .pending)
				} catch {
					logger.warning("Deferred credential was saved, but its pending placeholder could not be removed: \(error.localizedDescription)")
				}
			} else if pds == nil {
				do {
					try await storage.removePendingOrDeferredDoc(id: issueReq.id)
				} catch {
					// Failure to remove an obsolete placeholder must not invalidate a
					// credential whose data and key batch are already committed.
					logger.warning("Credential was saved, but its obsolete pending/deferred placeholder could not be removed: \(error.localizedDescription)")
				}
			}
			let transactionMetadata = docMetadata.redactedForTransactionLog().toData()
			await logIssuanceTransaction(status: .completed, format: format, issuerName: issuerName, issuerIdentifier: issuerIdentifier, issuerLogoUrl: issuerLogoUrl, documentId: newDocument.id, docType: newDocument.docType, docDisplayName: newDocument.displayName, docMetadata: transactionMetadata)
			// Notify issuer of successful credential acceptance (fire-and-forget, after storage completes)
			if let notificationId = issuedNotificationId, let authorized = issuedAuthorizedRequest, let issuer {
				sendIssuanceNotification(issuer: issuer, authorized: authorized, notificationId: notificationId, event: .credentialAccepted)
			}
			return newDocument
		} catch {
			// Notify issuer of credential failure if the issuer sent a notification_id (fire-and-forget)
			if let notificationId = issuedNotificationId, let authorized = issuedAuthorizedRequest, let issuer {
				sendIssuanceNotification(issuer: issuer, authorized: authorized, notificationId: notificationId, event: .credentialFailure, eventDescription: error.localizedDescription)
			}
			await logIssuanceTransaction(status: .failed, format: format, issuerName: issuerName, issuerIdentifier: issuerIdentifier, issuerLogoUrl: issuerLogoUrl, docType: docType, errorMessage: error.localizedDescription)
			throw error
		}
	}

	private func sendIssuanceNotification(issuer: any IssuerType, authorized: AuthorizedRequest, notificationId: String, event: NotifiedEvent, eventDescription: String? = nil) {
		Task {
			do {
				let notifId = try NotificationId(value: notificationId)
				try await issuer.notify(
					authorizedRequest: authorized,
					notification: NotificationObject(id: notifId, event: event, eventDescription: eventDescription),
					dPopNonce: nil
				)
				logger.info("Issuance notification sent: \(event)")
			} catch {
				logger.warning("Issuance notification failed (non-blocking): \(error)")
			}
		}
	}

	private func logIssuanceTransaction(status: TransactionLog.Status, format: DocDataFormat, issuerName: String?, issuerIdentifier: String?, issuerLogoUrl: String?, documentId: String? = nil, docType: String? = nil, docDisplayName: String? = nil, docMetadata: Data? = nil, errorMessage: String? = nil) async {
		guard let transactionLogger else { return }
		let issuingParty = TransactionLog.IssuingParty(name: issuerName ?? "Unknown Issuer", identifier: issuerIdentifier ?? "", logoUrl: issuerLogoUrl)
		let dataFormat = TransactionLog.DataFormat(format)
		let transactionLog = TransactionLog(timestamp: TransactionLogUtils.getTimestamp(), status: status, errorMessage: errorMessage, issuingParty: issuingParty, type: .issuance, dataFormat: dataFormat, docMetadata: docMetadata != nil ? [docMetadata] : nil, documentId: documentId, docType: docType, displayName: docDisplayName)
		do {
			try await transactionLogger.log(transaction: transactionLog)
		} catch {
			logger.error("Failed to log issuance transaction: \(error)")
		}
	}

	func validateIssuedDocuments(_ issued: WalletStorage.Document, batch: [WalletStorage.Document]?, publicKeys: [Data]) async throws {
		var pkCoseKeys = publicKeys.compactMap { try? CoseKey(data: [UInt8]($0)) }
		guard pkCoseKeys.count == publicKeys.count else { throw PresentationSession.makeError(str: "Failed to parse public keys") }
		for doc in (batch ?? [issued]) {
			if doc.docDataFormat == .cbor {
				let iss = try IssuerSigned(data: [UInt8](doc.data))
				try iss.validate(docType: doc.docType, publicCoseKeys: &pkCoseKeys)
			} else if doc.docDataFormat == .sdjwt {
				try await validateIssuedSdJwt(doc, publicCoseKeys: &pkCoseKeys)
			}
		}
		guard pkCoseKeys.isEmpty else {
			throw PresentationSession.makeError(str: "Issued credentials did not bind all provided public keys")
		}
	}

	private func validateIssuedSdJwt(_ document: WalletStorage.Document, publicCoseKeys: inout [CoseKey]) async throws {
		guard let serialized = String(data: document.data, encoding: .utf8) else {
			throw PresentationSession.makeError(str: "Failed to decode SD-JWT credential data")
		}
		try Self.validateSdJwtBindingKeys(serialized, publicCoseKeys: &publicCoseKeys)
		let expectedIssuer = try expectedSdJwtIssuerURL()
		let signedSdJwt = try CompactParser().getSignedSdJwt(serialisedString: serialized)
		try validateSdJwtIssuer(serialized, expectedIssuer: expectedIssuer)
		let verifier = SDJWTVerifier(sdJwt: signedSdJwt)
		// Determine the issuer public key: prefer x5c certificate chain, fall back to metadata
		let issuerKey: any KeyExpressible
		if let x5cChain = signedSdJwt.jwt.protectedHeader.x509CertificateChain, !x5cChain.isEmpty {
			issuerKey = try validateX5cChain(x5cChain, expectedIssuer: expectedIssuer)
		} else {
			let issuerNetworking = networking
			let metadataFetcher = SdJwtVcIssuerMetaDataFetcher(session: SdJwtNetworkingAdapter(
				dataFrom: { try await issuerNetworking.data(from: $0) },
				dataFor: { try await issuerNetworking.data(for: $0) }
			))
			let metadata = try await metadataFetcher.fetchIssuerMetaData(issuer: expectedIssuer)
			guard let kid = signedSdJwt.jwt.protectedHeader.keyID else {
				throw PresentationSession.makeError(str: "Issued SD-JWT is missing both x5c chain and key identifier")
			}
			guard let issuerJwk = metadata?.jwks.first(where: { $0.keyID == kid }) else {
				throw PresentationSession.makeError(str: "Unable to resolve issuer signing key for issued SD-JWT")
			}
			issuerKey = issuerJwk
		}
		let result = try verifier.verifyIssuance(
			issuersSignatureVerifier: { jws in try SignatureVerifier(signedJWT: jws, publicKey: issuerKey) },
			claimVerifier: { nbf, exp in ClaimsVerifier(nbf: nbf, exp: exp) }
		)
		try validateVerificationResult(result)
	}

	static func validateSdJwtBindingKeys(_ serialized: String, publicCoseKeys: inout [CoseKey]) throws {
		let cnfKeys = try SdJwtUtils.parseCnfBindingKeys(fromSerializedCredential: serialized)
		for key in cnfKeys {
			guard let x = Data(base64URLEncoded: key.x), let y = Data(base64URLEncoded: key.y) else {
				throw PresentationSession.makeError(str: "Issued SD-JWT cnf JWK has invalid key coordinates")
			}
			let keyX963 = MdocDataModel18013.CoseKey.x963Representation(x: x, y: y)
			guard let index = publicCoseKeys.firstIndex(where: { $0.x963Representation == keyX963 }) else {
				throw PresentationSession.makeError(str: "Failed to find matching public key for SD-JWT cnf binding key")
			}
			publicCoseKeys.remove(at: index)
		}
	}

	private func validateVerificationResult(_ result: Result<SignedSDJWT, any Error>) throws {
		guard case .success = result else {
			let error = switch result {
			case .failure(let error): error
			case .success: PresentationSession.makeError(str: "Unexpected SD-JWT verification result")
			}
			throw error
		}
	}

	private func expectedSdJwtIssuerURL() throws -> URL {
		guard let issuer = config.credentialIssuerURL,
			  let issuerURL = URL(string: issuer),
			  issuerURL.scheme != nil,
			  issuerURL.host != nil else {
			throw PresentationSession.makeError(str: "credentialIssuerURL must be a valid URL to verify SD-JWT credentials")
		}
		return issuerURL
	}

	private func validateSdJwtIssuer(_ serialized: String, expectedIssuer: URL) throws {
		let (_, payload, _) = SdJwtUtils.extractJWTParts(serialized)
		guard let payloadData = Data(base64URLEncoded: payload) else {
			throw PresentationSession.makeError(str: "Failed to decode SD-JWT payload")
		}
		let payloadJson = try JSON(data: payloadData)
		guard let issuer = payloadJson["iss"].string,
			  let issuerURL = URL(string: issuer),
			  issuerURL.scheme != nil,
			  issuerURL.host != nil else {
			throw PresentationSession.makeError(str: "Issued SD-JWT is missing a valid issuer")
		}
		guard normalized(url: issuerURL) == normalized(url: expectedIssuer) else {
			throw PresentationSession.makeError(str: "Issued SD-JWT issuer does not match the configured credential issuer")
		}
	}

	/// Validates the x5c chain against the configured trust anchors and returns the leaf public key.
	private func validateX5cChain(_ x5cChain: [String], expectedIssuer: URL) throws -> SecKey {
		let certsData = x5cChain.compactMap { Data(base64Encoded: $0) }
		guard certsData.count == x5cChain.count else {
			throw PresentationSession.makeError(str: "Invalid base64 encoding in SD-JWT x5c certificate chain")
		}
		let secCerts = certsData.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
		guard secCerts.count == certsData.count else {
			throw PresentationSession.makeError(str: "Failed to parse certificates in SD-JWT x5c chain")
		}
		guard let trustedRoots = config.trustedIssuerCertificates, !trustedRoots.isEmpty else {
			throw PresentationSession.makeError(str: "No trusted issuer certificates configured to validate SD-JWT x5c chain")
		}
		let validation = SecurityHelpers.isMdocX5cValid(
			secCerts: secCerts,
			usage: .mdocAuth,
			revocationPolicy: config.issuerCertificateRevocationPolicy,
			rootIaca: trustedRoots
		)
		guard validation.isValid else {
			let detail = validation.validationMessages.joined(separator: "; ")
			throw PresentationSession.makeError(str: "SD-JWT x5c certificate chain validation failed: \(detail)")
		}
		try validateIssuerCertificateIdentity(secCerts[0], expectedIssuer: expectedIssuer)
		guard let secKey = SecCertificateCopyKey(secCerts[0]) else {
			throw PresentationSession.makeError(str: "Unable to extract public key from SD-JWT x5c leaf certificate")
		}
		return secKey
	}

	private func validateIssuerCertificateIdentity(_ certificate: SecCertificate, expectedIssuer: URL) throws {
		guard let expectedHost = expectedIssuer.host?.lowercased() else {
			throw PresentationSession.makeError(str: "Configured credential issuer has no host")
		}
		let parsedCertificate = try certificate.certificate()
		let subjectAlternativeNames = try parsedCertificate.extensions.subjectAlternativeNames ?? SubjectAlternativeNames()
		let issuerHasPath = !expectedIssuer.path.isEmpty && expectedIssuer.path != "/"
		let issuerIdentityNames = subjectAlternativeNames.filter { name in
			switch name {
			case .uniformResourceIdentifier, .dnsName: true
			default: false
			}
		}
		if issuerIdentityNames.isEmpty,
			config.issuerCertificateIdentityValidation == .whenPresent {
			return
		}
		let identityMatches = issuerIdentityNames.contains { name in
			switch name {
			case .uniformResourceIdentifier(let value):
				guard let url = URL(string: value) else { return false }
				return normalized(url: url) == normalized(url: expectedIssuer)
			case .dnsName(let value):
				return !issuerHasPath && Self.dnsName(value, matches: expectedHost)
			default:
				return false
			}
		}
		guard identityMatches else {
			throw PresentationSession.makeError(str: "SD-JWT issuer certificate identity does not match the configured credential issuer")
		}
	}

	private static func dnsName(_ certificateName: String, matches host: String) -> Bool {
		let certificateName = certificateName.lowercased()
		guard certificateName.hasPrefix("*.") else { return certificateName == host }
		let suffix = String(certificateName.dropFirst(2))
		guard host.hasSuffix("." + suffix) else { return false }
		return host.split(separator: ".").count == suffix.split(separator: ".").count + 1
	}

	private func normalized(url: URL) -> String {
		let absoluteString = url.absoluteString
		return absoluteString.hasSuffix("/") ? String(absoluteString.dropLast()) : absoluteString
	}
	func hasIssuerUrl(_ issuerURL: String) -> Bool {
		guard let configURL = config.credentialIssuerURL else { return false }
		// Normalize by removing trailing slashes for comparison
		let normalizedConfig = configURL.hasSuffix("/") ? String(configURL.dropLast()) : configURL
		let normalizedInput = issuerURL.hasSuffix("/") ? String(issuerURL.dropLast()) : issuerURL
		return normalizedConfig == normalizedInput
	}

} // end of OpenId4VCIService

fileprivate extension URL {
	func getQueryStringParameter(_ parameter: String) -> String? {
		guard let url = URLComponents(string: self.absoluteString) else { return nil }
		return url.queryItems?.first(where: { $0.name == parameter })?.value
	}
}

extension WalletError {
	public static func authRequestFailed(error: Error) -> WalletError {
		if let wae = error as? ASWebAuthenticationSessionError {
			if wae.code == .canceledLogin { return WalletError(description: "The login has been cancelled.", localizationKey: "login_cancelled")  }
			else if wae.code == .presentationContextNotProvided { return WalletError(description: "Web authentication presentation context not provided.") }
			else if wae.code == .presentationContextInvalid { return WalletError(description: "Web authentication presentation context invalid.") }
			else { return WalletError(description: wae.localizedDescription) }
		}
		return WalletError(description:"Authorization request failed: \(error.localizedDescription)")

	}
}

struct OpenID4VCINetworking: Networking {
	static let maximumProtocolResponseBytes = 32 * 1_024 * 1_024
	let networking: any BoundedNetworkingProtocol

	init(networking: any BoundedNetworkingProtocol) {
		self.networking = networking
	}

	func data(from url: URL) async throws -> (Data, URLResponse) {
		try await data(for: URLRequest(url: url))
	}

	func data(for request: URLRequest) async throws -> (Data, URLResponse) {
		try await data(for: request, maximumResponseBytes: Self.maximumProtocolResponseBytes)
	}

	func data(for request: URLRequest, maximumResponseBytes: Int) async throws -> (Data, URLResponse) {
		guard let requestURL = request.url else {
			throw WalletError(description: "Protocol request has no URL")
		}
		try EudiWallet.validateHTTPSRemoteURL(requestURL, purpose: "OpenID4VCI request")
		let result = try await networking.data(for: request, maximumResponseBytes: maximumResponseBytes)
		if let finalURL = result.1.url {
			try EudiWallet.validateHTTPSRemoteURL(finalURL, purpose: "OpenID4VCI response")
		}
		return result
	}
}

extension Array where Element == OpenId4VciService {
	public func getByIssuerURL(_ issuerURL: String) async -> OpenId4VciService? {
		for service in self {
			if await service.hasIssuerUrl(issuerURL) {
				return service
			}
		}
		return nil
	}
}

/// Registry for OpenId4VCI services
@available(*, deprecated, message: "Process-global VCI registration is unsafe for multiple wallets. Use EudiWallet registration APIs instead.")
public final class OpenId4VCIServiceRegistry: @unchecked Sendable {
	public static let shared = OpenId4VCIServiceRegistry()
	private var services: [String: OpenId4VciService] = [:]
	private let lock = NSRecursiveLock()

	private init() {}

	public func register(name: String, service: OpenId4VciService) {
		lock.lock()
		defer { lock.unlock() }
		services[name] = service
	}

	public func get(name: String) -> OpenId4VciService? {
		lock.lock()
		defer { lock.unlock() }
		return services[name]
	}

	public func getAllNames() -> [String] {
		lock.lock()
		defer { lock.unlock() }
		return Array(services.keys)
	}

	public func getAllServices() -> [OpenId4VciService] {
		lock.lock()
		defer { lock.unlock() }
		return Array(services.values)
	}

	public func getByIssuerURL(issuerURL: String) async -> OpenId4VciService? {
		return await getAllServices().getByIssuerURL(issuerURL)
	}
}
