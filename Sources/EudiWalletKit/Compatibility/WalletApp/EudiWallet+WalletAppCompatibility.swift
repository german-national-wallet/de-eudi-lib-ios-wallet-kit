//
//  EudiWallet+WalletAppCompatibility.swift
//  EudiWalletKit
//

import Foundation
import MdocDataModel18013
import WalletStorage

extension EudiWallet {
	@MainActor
	@discardableResult public func issuePAR(issuerName: String, docTypeIdentifier: DocTypeIdentifier, credentialOptions: CredentialOptions?, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> WalletStorage.Document? {
		let vciService = try await resolveVCIService(issuerName: issuerName)
		return try await vciService.issuePAR(docTypeIdentifier, credentialOptions: credentialOptions, keyOptions: keyOptions, promptMessage: promptMessage)
	}

	/// Resume a pending authorization-code issuance after validating its OAuth state.
	///
	/// `authorizationState` must be the `state` value returned with the authorization
	/// callback. Calls that omit it fail closed for source compatibility with older clients.
	@MainActor
	@discardableResult public func resumePendingIssuanceDocuments(issuerName: String, pendingDoc: WalletStorage.Document, authorizationCode: String, authorizationState: String, nonce: String?, docTypeIdentifiers: [DocTypeIdentifier], credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {
		let vciService = try await resolveVCIService(issuerName: issuerName)
		return try await vciService.resumePendingIssuanceDocuments(
			pendingDoc: pendingDoc,
			authorizationCode: authorizationCode,
			authorizationState: authorizationState,
			nonce: nonce,
			docTypeIdentifiers: docTypeIdentifiers,
			credentialOptions: credentialOptions,
			keyOptions: keyOptions,
			promptMessage: promptMessage
		)
	}

	/// Compatibility overload for clients compiled against the pre-state API.
	/// A saved OAuth state is mandatory to prevent callback substitution.
	@available(*, deprecated, message: "Pass the authorizationState returned by the authorization callback")
	@MainActor
	@discardableResult public func resumePendingIssuanceDocuments(issuerName: String, pendingDoc: WalletStorage.Document, authorizationCode: String, nonce: String?, docTypeIdentifiers: [DocTypeIdentifier], credentialOptions: CredentialOptions, keyOptions: KeyOptions? = nil, promptMessage: String? = nil) async throws -> [WalletStorage.Document] {
		throw WalletError(description: "authorizationState is required to resume pending issuance securely")
	}

	public func storedAuthorizedRequestParams(docId: WalletStorage.Document.ID) async throws -> AuthorizedRequestParams? {
		let docMetadata = try await getDocumentMetadata(documentId: docId)
		guard let data = docMetadata.authorizedRequestData,
			  let authorizedData = try? JSONDecoder().decode(AuthorizedRequestData.self, from: data) else {
			return nil
		}
		return AuthorizedRequestParams(from: authorizedData.toAuthorizedRequest())
	}

	@MainActor
	@discardableResult public func getCredentialsWithRefreshToken(issuerName: String, docTypeIdentifiers: [DocTypeIdentifier], authorizedRequestParams: AuthorizedRequestParams, issuerDPopConstructorParam: IssuerDPoPConstructorParam, docIds: [String], credentialOptions: CredentialOptions? = nil, keyOptions: KeyOptions? = nil, promptMessage: String? = nil, forceRefreshToken: Bool = false) async throws -> (documents: [WalletStorage.Document], authorizedRequestParams: AuthorizedRequestParams) {
		let vciService = try await resolveVCIService(issuerName: issuerName)
		let authorized = try authorizedRequestParams.toAuthorizedRequest()
		let (documents, refreshed) = try await vciService.getCredentialsWithRefreshToken(
			docTypeIdentifiers: docTypeIdentifiers,
			authorized: authorized,
			issuerDPopConstructorParam: issuerDPopConstructorParam,
			docIds: docIds,
			credentialOptions: credentialOptions,
			keyOptions: keyOptions,
			promptMessage: promptMessage,
			forceRefreshToken: forceRefreshToken
		)
		return (documents, AuthorizedRequestParams(from: refreshed))
	}
}
