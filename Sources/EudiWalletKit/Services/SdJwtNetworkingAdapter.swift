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
import protocol eudi_lib_sdjwt_swift.Networking

struct SdJwtNetworkingAdapter: Networking {
	private let dataFrom: @Sendable (URL) async throws -> (Data, URLResponse)
	private let dataFor: @Sendable (URLRequest) async throws -> (Data, URLResponse)

	init(
		dataFrom: @escaping @Sendable (URL) async throws -> (Data, URLResponse),
		dataFor: @escaping @Sendable (URLRequest) async throws -> (Data, URLResponse)
	) {
		self.dataFrom = dataFrom
		self.dataFor = dataFor
	}

	func data(from url: URL) async throws -> (Data, URLResponse) {
		try await dataFrom(url)
	}

	func data(for request: URLRequest) async throws -> (Data, URLResponse) {
		try await dataFor(request)
	}
}
