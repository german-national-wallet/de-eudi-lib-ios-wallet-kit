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

/// A service registry owned by one wallet instance.
///
/// Issuance services hold wallet-specific storage, networking, trust policy,
/// and transaction logging dependencies. Keeping them in a process-wide
/// registry can therefore route one wallet's operation through another
/// wallet's dependencies when both register the same issuer name.
final class WalletOpenId4VciServiceRegistry: @unchecked Sendable {
	private let lock = NSLock()
	private var services: [String: OpenId4VciService] = [:]
	private var namesByIssuerURL: [String: String] = [:]

	func register(name: String, issuerURL: String?, service: OpenId4VciService) throws {
		try lock.withLock {
			let normalizedIssuerURL = issuerURL.flatMap(Self.normalizeIssuerURL)
			if let normalizedIssuerURL,
			   let existingName = namesByIssuerURL[normalizedIssuerURL],
			   existingName != name {
				throw WalletError(description: "Issuer URL \(issuerURL ?? normalizedIssuerURL) is already registered as \(existingName)")
			}
			// Re-registering a name replaces its service and removes any stale URL index.
			let staleURLs = namesByIssuerURL.compactMap { $0.value == name ? $0.key : nil }
			for url in staleURLs { namesByIssuerURL.removeValue(forKey: url) }
			services[name] = service
			if let normalizedIssuerURL {
				namesByIssuerURL[normalizedIssuerURL] = name
			}
		}
	}

	func get(name: String) -> OpenId4VciService? {
		lock.withLock { services[name] }
	}

	func getAllServices() -> [OpenId4VciService] {
		lock.withLock { Array(services.values) }
	}

	func getByIssuerURL(_ issuerURL: String) -> OpenId4VciService? {
		guard let normalizedIssuerURL = Self.normalizeIssuerURL(issuerURL) else { return nil }
		return lock.withLock {
			guard let name = namesByIssuerURL[normalizedIssuerURL] else { return nil }
			return services[name]
		}
	}

	private static func normalizeIssuerURL(_ value: String) -> String? {
		guard var components = URLComponents(string: value),
			let scheme = components.scheme?.lowercased(),
			let host = components.host?.lowercased() else { return nil }
		components.scheme = scheme
		components.host = host
		components.fragment = nil
		if (scheme == "https" && components.port == 443) || (scheme == "http" && components.port == 80) {
			components.port = nil
		}
		while components.path.count > 1 && components.path.hasSuffix("/") {
			components.path.removeLast()
		}
		return components.url?.absoluteString
	}
}
