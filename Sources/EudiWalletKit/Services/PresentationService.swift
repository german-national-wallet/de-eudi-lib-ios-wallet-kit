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
import MdocDataTransfer18013
import struct WalletStorage.Document

/// [Doc Types to [Namespace to Items]] dictionary
public typealias RequestItems = MdocDataTransfer18013.RequestItems

/// Presentation service abstract protocol

public protocol PresentationService: Sendable {
	/// Status of the data transfer
	//var status: TransferStatus { get }
	/// instance of a presentation ``FlowType``
	var flow: FlowType { get }
	/// Generate a QR code to be shown to verifier (optional)
	func startQrEngagement(secureAreaName: String?, keyOptions: KeyOptions) async throws -> String
	/// Receive request.
	func receiveRequest() async throws -> [UserRequestInfo]

	var transactionLog: TransactionLog { get }
	
	var  zkpDocumentIds: [Document.ID]? { get }

	/// Send response to verifier
	/// - Parameters:
	///   - userAccepted: True if user accepted to send the response
	///   - itemsToSend: The selected items to send organized in document types and namespaces (see ``RequestItems``)
	func sendResponse(userAccepted: Bool, itemsToSend: RequestItems, onSuccess: ( @Sendable (URL?) -> Void)?) async throws
	
	/// wait for disconnect
	func waitForDisconnect() async throws
}

public protocol NetworkingProtocol: Sendable {
	func data(from url: URL) async throws -> (Data, URLResponse)
	func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

/// Networking capable of enforcing a response limit while bytes are streamed.
/// Custom wallet networking should adopt this protocol to handle untrusted
/// OpenID metadata, request objects, status lists, and credential images.
public protocol BoundedNetworkingProtocol: NetworkingProtocol {
	/// Fetch a response while enforcing the byte limit during transfer. Conformers
	/// must stop reading as soon as the limit would be exceeded; a post-download
	/// size check is not sufficient for untrusted protocol responses.
	func data(for request: URLRequest, maximumResponseBytes: Int) async throws -> (Data, URLResponse)
}

extension URLSession: NetworkingProtocol, BoundedNetworkingProtocol {
	public func data(for request: URLRequest, maximumResponseBytes: Int) async throws -> (Data, URLResponse) {
		guard maximumResponseBytes >= 0 else {
			throw WalletError(description: "Maximum response size cannot be negative")
		}
		let (bytes, response) = try await bytes(for: request)
		let expectedLength = response.expectedContentLength
		if expectedLength > Int64(maximumResponseBytes) {
			throw WalletError(description: "Network response exceeds the configured size limit")
		}
		var data = Data()
		data.reserveCapacity(min(maximumResponseBytes, max(0, Int(expectedLength))))
		for try await byte in bytes {
			guard data.count < maximumResponseBytes else {
				throw WalletError(description: "Network response exceeds the configured size limit")
			}
			data.append(byte)
		}
		return (data, response)
	}
}
