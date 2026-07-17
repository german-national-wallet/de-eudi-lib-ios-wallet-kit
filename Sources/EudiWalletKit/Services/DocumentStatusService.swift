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
import StatiumSwift

public actor DocumentStatusService {
	let statusIdentifier: StatusIdentifier
	let verifier: (any VerifyStatusListTokenSignature)?
	let date: Date
	let clockSkew: TimeInterval
	let networkingService: any NetworkingServiceType

	public init(statusIdentifier: StatusIdentifier, date: Date = .now, clockSkew: TimeInterval = 60, verifier: any VerifyStatusListTokenSignature, networkingService: (any NetworkingServiceType)? = nil) {
		self.statusIdentifier = statusIdentifier
		self.verifier = verifier
		self.date = date
		self.clockSkew = clockSkew
		self.networkingService = networkingService ?? StatusNetworkingAdapter(networking: URLSession.shared)
	}

	/// Compatibility initializer. Prefer the overload with a required verifier.
	@available(*, deprecated, message: "Pass a status-list signature verifier explicitly")
	public init(statusIdentifier: StatusIdentifier, date: Date = .now, clockSkew: TimeInterval = 60, verifier: (any VerifyStatusListTokenSignature)? = nil, networkingService: (any NetworkingServiceType)? = nil) {
		self.statusIdentifier = statusIdentifier
		self.verifier = verifier
		self.date = date
		self.clockSkew = clockSkew
		self.networkingService = networkingService ?? StatusNetworkingAdapter(networking: URLSession.shared)
	}

	public func getStatus() async throws -> CredentialStatus {
		guard let verifier else {
			throw WalletError(description: "A status-list signature verifier is required; use the verifier initializer")
		}
		guard let statusReference: StatusReference = .init(idx: statusIdentifier.idx, uriString: statusIdentifier.uriString) else {
			throw WalletError(description: "Invalid status identifier")
		}
		try EudiWallet.validateHTTPSRemoteURL(statusReference.uri, purpose: "Status list")
		let getStatus = GetStatus()
		let tokenFetcher = StatusListTokenFetcher(networkingService: networkingService, verifier: verifier, date: date)
		let result = try await getStatus.getStatus(index: statusReference.idx, url: statusReference.uri, fetchClaims: tokenFetcher.getStatusClaims, clockSkew: clockSkew).get()
		return result
	}
}
