/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

import Foundation
import StatiumSwift

/// Routes status-list requests through the wallet application's injected network stack.
struct StatusNetworkingAdapter: NetworkingServiceType {
	let session: URLSession = .shared
	private let networking: any BoundedNetworkingProtocol

	init(networking: any BoundedNetworkingProtocol) {
		self.networking = networking
	}

	func get(url: URL, headers: [String: String]) async -> Result<Data, NetworkingError> {
		do {
			try EudiWallet.validateHTTPSRemoteURL(url, purpose: "Status list")
			var request = URLRequest(url: url)
			request.httpMethod = "GET"
			for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }
			let (data, response) = try await networking.data(for: request, maximumResponseBytes: 16 * 1_024 * 1_024)
			guard let httpResponse = response as? HTTPURLResponse,
				httpResponse.statusCode == 200,
				let finalURL = httpResponse.url else {
				return .failure(.error("Bad server response"))
			}
			try EudiWallet.validateHTTPSRemoteURL(finalURL, purpose: "Status list response")
			return .success(data)
		} catch {
			return .failure(.error(error.localizedDescription))
		}
	}
}
