//
//  OpenId4VciService+WalletAppCompatibility.swift
//  EudiWalletKit
//

import Foundation
import OpenID4VCI
import MdocDataModel18013
import JOSESwift
import Security
import WalletStorage

private struct IndexedCompatibilityDocument: Sendable {
	let index: Int
	let document: WalletStorage.Document
}

extension OpenId4VciService {
	func issuePAR(_ docTypeIdentifier: DocTypeIdentifier, credentialOptions: CredentialOptions?, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> WalletStorage.Document? {
		let operationToken = try beginExclusiveIssuanceOperation()
		defer { endExclusiveIssuanceOperation(operationToken) }
		let usedCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifier, credentialOptions: credentialOptions)
		try await prepareIssuing(
			id: UUID().uuidString,
			docTypeIdentifier: docTypeIdentifier,
			displayName: nil,
			credentialOptions: usedCredentialOptions,
			keyOptions: keyOptions,
			disablePrompt: false,
			promptMessage: promptMessage
		)

		let (credentialConfigurations, offer) = try await buildCredentialOffer(for: [docTypeIdentifier])
		guard let configuration = credentialConfigurations.first else {
			throw PresentationSession.makeError(str: "Invalid credential configuration for \(docTypeIdentifier.docType ?? docTypeIdentifier.vct ?? "")")
		}

		let issuer = try await getIssuerForWalletAppCompatibility(offer: offer, useDpop: false)
		let parPlaced = try await issuer.prepareAuthorizationRequest(credentialOffer: offer)
		authRequested = parPlaced

		let metadataKey = UUID().uuidString
		cache.store(offer, for: metadataKey)

		let outcome = IssuanceOutcome.pending(
			PendingIssuanceModel(
					pendingReason: .presentation_request_url(parPlaced.authorizationCodeURL.url.absoluteString),
					configuration: configuration,
					metadataKey: metadataKey,
					offerRequestJSON: try Self.makeCredentialOfferRequestJSON(offer),
				pckeCodeVerifier: parPlaced.pkceVerifier.codeVerifier,
				pckeCodeVerifierMethod: parPlaced.pkceVerifier.codeVerifierMethod,
				state: parPlaced.state
			)
		)

		return try await finalizeIssuing(
			issueOutcome: outcome,
			docType: docTypeIdentifier.docType,
			format: configuration.format,
			issueReq: issueReq,
			deleteId: nil
		)
	}

	func resumePendingIssuanceDocuments(pendingDoc: WalletStorage.Document, authorizationCode: String, authorizationState: String, nonce: String?, docTypeIdentifiers: [DocTypeIdentifier], credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {
		guard pendingDoc.status == .pending else {
			throw PresentationSession.makeError(str: "Invalid document status for pending issuance: \(pendingDoc.status)")
		}
		let operationToken = try beginExclusiveIssuanceOperation()
		defer { endExclusiveIssuanceOperation(operationToken) }
		try beginIssuanceResume(id: pendingDoc.id, status: .pending)
		defer { endIssuanceResume(id: pendingDoc.id, status: .pending) }
		let storedPendingDoc = try await persistedPlaceholder(matching: pendingDoc, status: .pending)

		let model = try JSONDecoder().decode(PendingIssuanceModel.self, from: storedPendingDoc.data)
		try validateConfiguredIssuer(model.configuration.credentialIssuerIdentifier)
		guard case .presentation_request_url = model.pendingReason else {
			throw WalletError(description: "Unknown pending reason: \(model.pendingReason)")
		}
		let validatedAuthorizationState = try Self.validateAuthorizationState(authorizationState, expectedState: model.state)
		let offer: CredentialOffer
		if let cachedOffer = cache.credentialOffer(for: model.metadataKey) {
			offer = cachedOffer
		} else if let requestJSON = model.offerRequestJSON {
			offer = try await resolvePersistedCredentialOffer(requestJSON)
		} else {
			throw WalletError(description: "Pending issuance cannot be completed")
		}
		try validateConfiguredIssuer(offer.credentialIssuerIdentifier.url.absoluteString)

		let (credentialIssuerIdentifier, metadata) = try await resolveIssuerMetadata()
		guard let authorizationServer = metadata.authorizationServers?.first else {
			throw PresentationSession.makeError(str: "Invalid authorization server - no authorization server found")
		}

		let authServerMetadata = await AuthorizationServerMetadataResolver(
			oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking),
			oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)
		).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()

		let credentialConfigurations = try docTypeIdentifiers.map {
			try getCredentialConfiguration(
				credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString,
				issuerDisplay: metadata.display,
				credentialsSupported: metadata.credentialsSupported,
				identifier: $0.configurationIdentifier,
				docType: $0.docType,
				vct: $0.vct,
				batchCredentialIssuance: metadata.batchCredentialIssuance,
				dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map(\.name),
				clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map(\.name)
			)
		}

		let uiCulture = self.uiCulture
		let config = self.config
		let networking = self.networking
		let storage = self.storage
		let storageService = self.storageService
		let transactionLogger = self.transactionLogger
		let cache = self.cache

		let docTypes = credentialConfigurations.map {
			OfferedDocModel(
				credentialConfigurationIdentifier: $0.configurationIdentifier.value,
				docType: $0.docType,
				vct: $0.vct,
				scope: $0.scope ?? "",
				identifier: $0.configurationIdentifier.value,
				displayName: $0.display.getName(uiCulture) ?? $0.docType ?? $0.vct ?? $0.scope ?? "",
				algValuesSupported: $0.credentialSigningAlgValuesSupported,
				claims: $0.claims,
				credentialOptions: credentialOptions,
				keyOptions: keyOptions
			)
		}

		let storedDpopKeyId = DocMetadata(from: storedPendingDoc.metadata)?.dpopKeyId
		let issuer = try await getIssuerForWalletAppCompatibility(
			offer: offer,
			nonce: nonce,
			dpopKeyId: storedDpopKeyId,
			dpopKeyOptions: keyOptions.map { KeyOptions(curve: $0.curve, secureAreaName: $0.secureAreaName) }
		)
		let pkceVerifier = try PKCEVerifier(codeVerifier: model.pckeCodeVerifier, codeVerifierMethod: model.pckeCodeVerifierMethod)
		let authorizationCodeURL = try AuthorizationCodeURL(urlString: storedPendingDoc.authorizePresentationUrl ?? "")
		let request = AuthorizationRequested(
			credentials: [try .init(value: model.configuration.configurationIdentifier.value)],
			authorizationCodeURL: authorizationCodeURL,
			pkceVerifier: pkceVerifier,
			state: model.state,
			configurationIds: [model.configuration.configurationIdentifier],
			dpopNonce: nil
		)
		let authorized = try await issuer.authorizeWithAuthorizationCode(
			serverState: validatedAuthorizationState,
			request: request,
			authorizationCode: try AuthorizationCode(value: authorizationCode),
			authorizationDetailsInTokenRequest: .doNotInclude,
			grant: try offer.grants ?? .authorizationCode(try Grants.AuthorizationCode(authorizationServer: nil))
		)
		let issuerName = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getName(uiCulture) ?? offer.credentialIssuerIdentifier.url.host ?? offer.credentialIssuerIdentifier.url.absoluteString
		let issuerIdentifier = offer.credentialIssuerIdentifier.url.absoluteString
		let issuerLogoUrl = offer.credentialIssuerMetadata.display.map(\.displayMetadata).getLogo(uiCulture)?.uri?.absoluteString
		let tokenDpopKeyId = issueReq.dpopKeyId

		let documents = try await withThrowingTaskGroup(of: IndexedCompatibilityDocument.self) { group in
			for (index, docType) in docTypes.enumerated() {
				group.addTask {
					let service = try OpenId4VciService(
						uiCulture: uiCulture,
						config: config,
						networking: networking,
						storage: storage,
						storageService: storageService,
						transactionLogger: transactionLogger,
						cache: cache
					)
					do {
						guard let docTypeIdentifier = docType.docTypeIdentifier else {
							throw PresentationSession.makeError(str: "Missing credential identifier for pending issuance")
						}
						let usedCredentialOptions = try await service.validateCredentialOptions(
							docTypeIdentifier: docTypeIdentifier,
							credentialOptions: docType.credentialOptions,
							offer: offer
						)
						try await service.prepareIssuing(
							id: UUID().uuidString,
							docTypeIdentifier: docTypeIdentifier,
							displayName: index > 0 ? nil : docTypes.map(\.displayName).joined(separator: ", "),
							credentialOptions: usedCredentialOptions,
							keyOptions: docType.keyOptions,
							disablePrompt: index > 0,
							promptMessage: promptMessage
						)
						await service.setAdditionalOptions(docType.identifier ?? "")
						let (bindingKeys, publicKeys) = try await service.initSecurityKeys(credentialConfigurations[index], proofSubject: issuer.config.client.id)
						let outcome = try await service.issueDocumentByOfferUrl(
							issuer: issuer,
							offer: offer,
							authorizedOutcome: .authorized(authorized),
							configuration: credentialConfigurations[index],
							bindingKeys: bindingKeys,
							publicKeys: publicKeys,
							promptMessage: promptMessage
						)
						let document = try await service.finalizeIssuing(
							issueOutcome: outcome,
							docType: docType.docTypeOrVct,
							format: credentialConfigurations[index].format,
							issueReq: service.issueReq,
							deleteId: nil,
							issuer: issuer,
							dpopKeyId: tokenDpopKeyId,
							issuerName: issuerName,
							issuerIdentifier: issuerIdentifier,
							issuerLogoUrl: issuerLogoUrl
						)
						return IndexedCompatibilityDocument(index: index, document: document)
					} catch {
						await service.cleanupIssueRequestKeys()
						throw error
					}
				}
			}

			var indexedDocuments = [IndexedCompatibilityDocument]()
			for try await document in group {
				indexedDocuments.append(document)
			}
			try? await storage.removePendingOrDeferredDoc(id: storedPendingDoc.id)
			return indexedDocuments.sorted { $0.index < $1.index }.map(\.document)
		}
		cache.removeCredentialOffer(for: model.metadataKey)
		return documents
	}

	private func setAdditionalOptions(_ value: String) {
		issueReq.keyOptions?.additionalOptions = Data(value.utf8)
	}

	func getCredentialsWithRefreshToken(docTypeIdentifiers: [DocTypeIdentifier], authorized: AuthorizedRequest, issuerDPopConstructorParam: IssuerDPoPConstructorParam, docIds: [String], credentialOptions: CredentialOptions?, keyOptions: KeyOptions? = nil, promptMessage: String? = nil, forceRefreshToken: Bool = false) async throws -> ([WalletStorage.Document], AuthorizedRequest) {
		let operationToken = try beginExclusiveIssuanceOperation()
		defer { endExclusiveIssuanceOperation(operationToken) }
		guard !docTypeIdentifiers.isEmpty else { return ([], authorized) }
		guard docTypeIdentifiers.count == docIds.count else {
			throw WalletError(description: "Refresh token: docTypeIdentifiers (\(docTypeIdentifiers.count)) and docIds (\(docIds.count)) count mismatch")
		}
		let storedDpopKeyId = try await storageService.loadDocumentMetadata(id: docIds[0], status: .issued)?.dpopKeyId

		let anchorCredentialOptions = try await validateCredentialOptions(docTypeIdentifier: docTypeIdentifiers[0], credentialOptions: credentialOptions)
		try await prepareIssuing(
			id: UUID().uuidString,
			docTypeIdentifier: docTypeIdentifiers[0],
			displayName: nil,
			credentialOptions: anchorCredentialOptions,
			keyOptions: keyOptions,
			disablePrompt: false,
			promptMessage: promptMessage
		)

		let (credentialIssuerIdentifier, metadata) = try await resolveIssuerMetadata()
		guard let authorizationServer = metadata.authorizationServers?.first else {
			throw WalletError(description: "Invalid issuer metadata")
		}
		let authServerMetadata = await AuthorizationServerMetadataResolver(
			oidcFetcher: Fetcher<OIDCProviderMetadata>(session: networking),
			oauthFetcher: Fetcher<AuthorizationServerMetadata>(session: networking)
		).resolve(url: authorizationServer)
		let authorizationServerMetadata = try authServerMetadata.get()

		let credentialConfigurations = try docTypeIdentifiers.map {
			try getCredentialConfiguration(
				credentialIssuerIdentifier: credentialIssuerIdentifier.url.absoluteString,
				issuerDisplay: metadata.display,
				credentialsSupported: metadata.credentialsSupported,
				identifier: $0.configurationIdentifier,
				docType: $0.docType,
				vct: $0.vct,
				batchCredentialIssuance: metadata.batchCredentialIssuance,
				dpopSigningAlgValuesSupported: authorizationServerMetadata.dpopSigningAlgValuesSupported?.map { $0.name },
				clientAttestationPopSigningAlgValuesSupported: authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported?.map { $0.name }
			)
		}
		let offer = try CredentialOffer(
			credentialIssuerIdentifier: credentialIssuerIdentifier,
			credentialIssuerMetadata: metadata,
			credentialConfigurationIdentifiers: credentialConfigurations.map { $0.configurationIdentifier },
			grants: nil,
			authorizationServerMetadata: authorizationServerMetadata
		)
		let dpopConstructor = try makeIssuerDPoPConstructor(
			from: issuerDPopConstructorParam,
			supportedAlgorithms: authorizationServerMetadata.dpopSigningAlgValuesSupported
		)
		let issuer = try await getIssuerForWalletAppCompatibility(
			offer: offer,
			dpopKeyId: storedDpopKeyId,
			dpopKeyOptions: keyOptions.map { KeyOptions(curve: $0.curve, secureAreaName: $0.secureAreaName) },
			dpopConstructor: dpopConstructor
		)

		// Refresh the access token ONCE for the whole batch. The refresh_token grant keeps the original
		// authorization scope, so the re-minted token can request every configuration in the offer.
		let refreshed: AuthorizedRequest
		do {
			refreshed = try await refreshAuthorization(issuer: issuer, authorized: authorized, configuration: credentialConfigurations[0], forceRefreshToken: forceRefreshToken)
		} catch CredentialIssuanceError.requestFailed(let code, let error, let description) where (400..<500).contains(code) {
			throw RefreshAuthorizationError.reauthorizationRequired(statusCode: code, description: "\(error) \(description ?? "")")
		} catch PostError.requestError(let code, let error) where (400..<500).contains(code) {
			throw RefreshAuthorizationError.reauthorizationRequired(statusCode: code, description: "\(error)")
		}

		let uiCulture = self.uiCulture
		let config = self.config
		let networking = self.networking
		let storage = self.storage
		let storageService = self.storageService
		let transactionLogger = self.transactionLogger
		let cache = self.cache

		// Loop only the credential API call per identifier, under the single refreshed authorization.
		let documents = try await withThrowingTaskGroup(of: IndexedCompatibilityDocument.self) { group in
			for (index, docTypeIdentifier) in docTypeIdentifiers.enumerated() {
				let configuration = credentialConfigurations[index]
				let deleteId = docIds[index]
				group.addTask {
					let service = try OpenId4VciService(
						uiCulture: uiCulture,
						config: config,
						networking: networking,
						storage: storage,
						storageService: storageService,
						transactionLogger: transactionLogger,
						cache: cache
					)
					do {
					let usedCredentialOptions = try await service.validateCredentialOptions(
						docTypeIdentifier: docTypeIdentifier,
						credentialOptions: credentialOptions,
						offer: offer
					)
					try await service.prepareIssuing(
						id: UUID().uuidString,
						docTypeIdentifier: docTypeIdentifier,
						displayName: nil,
						credentialOptions: usedCredentialOptions,
						keyOptions: keyOptions,
						disablePrompt: index > 0,
						promptMessage: promptMessage
					)
					await service.setAdditionalOptions(configuration.configurationIdentifier.value)
					let (bindingKeys, publicKeys) = try await service.initSecurityKeys(configuration, proofSubject: issuer.config.client.id)
					let outcome = try await service.issueDocumentByOfferUrl(
						issuer: issuer,
						offer: offer,
						authorizedOutcome: .authorized(refreshed),
						configuration: configuration,
						bindingKeys: bindingKeys,
						publicKeys: publicKeys,
						promptMessage: promptMessage
					)
					let document = try await service.finalizeIssuing(
						issueOutcome: outcome,
						docType: docTypeIdentifier.docType,
						format: configuration.format,
						issueReq: service.issueReq,
						deleteId: deleteId,
						dpopKeyId: storedDpopKeyId
					)
					return IndexedCompatibilityDocument(index: index, document: document)
					} catch {
						await service.cleanupIssueRequestKeys()
						throw error
					}
				}
			}
			var documents = [IndexedCompatibilityDocument]()
			for try await document in group {
				documents.append(document)
			}
			return documents.sorted { $0.index < $1.index }.map(\.document)
		}
		logger.info("Refresh token: re-issued \(documents.count) credential(s) under one refreshed authorization")
		return (documents, refreshed)
	}

	private func makeIssuerDPoPConstructor(from parameter: IssuerDPoPConstructorParam, supportedAlgorithms: [JWSAlgorithm]?) throws -> DPoPConstructor {
		let declaredAlgorithm = parameter.jwk[JWKParameter.algorithm.rawValue]
		let algorithmName: String = switch parameter.jwk.keyType {
		case .EC:
			try resolveECSigningAlgorithm(
				curve: parameter.jwk[ECParameter.curve.rawValue],
				declaredAlgorithm: declaredAlgorithm
			)
		case .RSA:
			try resolveRSASigningAlgorithm(declaredAlgorithm)
		case .OCT:
			throw WalletError(description: "Symmetric JWKs cannot be used for DPoP")
		}
		guard SignatureAlgorithm(rawValue: algorithmName) != nil else {
			throw WalletError(description: "Unsupported DPoP signing algorithm: \(algorithmName)")
		}
		let algorithm = JWSAlgorithm.parse(algorithmName)
		if let supportedAlgorithms, !supportedAlgorithms.isEmpty,
		   !supportedAlgorithms.contains(where: { $0.name == algorithm.name }) {
			throw WalletError(description: "DPoP signing algorithm \(algorithm.name) is not supported by the authorization server")
		}
		return DPoPConstructor(
			algorithm: algorithm,
			jwk: parameter.jwk,
			privateKey: .secKey(parameter.privateKey)
		)
	}

	private func resolveECSigningAlgorithm(curve: String?, declaredAlgorithm: String?) throws -> String {
		let curveAlgorithm = switch curve {
		case ECCurveType.P256.rawValue: JWSAlgorithm(.ES256).name
		case ECCurveType.P384.rawValue: JWSAlgorithm(.ES384).name
		case ECCurveType.P521.rawValue: JWSAlgorithm(.ES512).name
		default: throw WalletError(description: "Unsupported DPoP EC curve: \(curve ?? "missing")")
		}
		guard declaredAlgorithm == nil || declaredAlgorithm == curveAlgorithm else {
			throw WalletError(description: "DPoP JWK algorithm \(declaredAlgorithm ?? "missing") does not match curve \(curve ?? "missing")")
		}
		return curveAlgorithm
	}

	private func resolveRSASigningAlgorithm(_ declaredAlgorithm: String?) throws -> String {
		let algorithm = declaredAlgorithm ?? JWSAlgorithm(.RS256).name
		guard algorithm.hasPrefix("RS") || algorithm.hasPrefix("PS") else {
			throw WalletError(description: "DPoP JWK algorithm \(algorithm) is not compatible with an RSA key")
		}
		return algorithm
	}

	private func getIssuerForWalletAppCompatibility(offer: CredentialOffer, nonce: String? = nil, dpopKeyId: String? = nil, useDpop: Bool? = nil, dpopKeyOptions: KeyOptions? = nil, dpopConstructor suppliedDPoPConstructor: DPoPConstructorType? = nil) async throws -> Issuer {
		var dpopConstructor = suppliedDPoPConstructor
		if dpopConstructor == nil, useDpop ?? config.requireDpop {
			guard let resolvedDpopKeyId = dpopKeyId ?? issueReq?.dpopKeyId else {
				throw PresentationSession.makeError(str: "Pending issuance metadata is missing its DPoP key identifier")
			}
			dpopConstructor = try await config.makePoPConstructor(
				popUsage: .dpop,
				privateKeyId: resolvedDpopKeyId,
				algorithms: offer.authorizationServerMetadata.dpopSigningAlgValuesSupported,
				keyOptions: dpopKeyOptions ?? config.dpopKeyOptions
			)
		}
		let vciConfig = try await config.toOpenId4VCIConfig(
			credentialIssuerId: offer.credentialIssuerIdentifier.url.absoluteString,
			clientAttestationPopSigningAlgValuesSupported: offer.authorizationServerMetadata.clientAttestationPopSigningAlgValuesSupported
		)
		_ = nonce
		return try Issuer(
			authorizationServerMetadata: offer.authorizationServerMetadata,
			issuerMetadata: offer.credentialIssuerMetadata,
			config: vciConfig,
			parPoster: Poster(session: networking),
			tokenPoster: Poster(session: networking),
			requesterPoster: Poster(session: networking),
			deferredRequesterPoster: Poster(session: networking),
			notificationPoster: Poster(session: networking),
			noncePoster: Poster(session: networking),
			dpopConstructor: dpopConstructor
		)
	}

}
