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

import Testing
@testable import EudiWalletKit
import Foundation
import MdocDataModel18013
import MdocSecurity18013
import Security
import SwiftCBOR
import SwiftyJSON
import WalletStorage

struct IssuanceTrustValidationTests {
	@Test("SD-JWT x5c validation requires configured trust anchors")
	func rejectsX5cWithoutTrustAnchors() async throws {
		let fixture = try makeFixture()
		let service = try makeService(issuerURL: fixture.issuerURL, trustedRoots: nil)

		await #expect(throws: (any Error).self) {
			try await service.validateIssuedDocuments(
				fixture.document,
				batch: nil,
				publicKeys: [fixture.publicKey]
			)
		}
	}

	@Test("SD-JWT issuer must match the configured credential issuer")
	func rejectsMismatchedIssuer() async throws {
		let fixture = try makeFixture()
		let service = try makeService(
			issuerURL: "https://unexpected-issuer.example",
			trustedRoots: try trustedRoots()
		)

		await #expect(throws: (any Error).self) {
			try await service.validateIssuedDocuments(
				fixture.document,
				batch: nil,
				publicKeys: [fixture.publicKey]
			)
		}
	}

	@Test("Strict certificate identity rejects signing certificates without issuer SANs")
	func strictIdentityRejectsMissingSan() async throws {
		let fixture = try makeFixture()
		let service = try makeService(
			issuerURL: fixture.issuerURL,
			trustedRoots: try trustedRoots(),
			identityValidation: .required
		)

		await #expect(throws: (any Error).self) {
			try await service.validateIssuedDocuments(
				fixture.document,
				batch: nil,
				publicKeys: [fixture.publicKey]
			)
		}
	}

	@Test("SD-JWT validation rejects unconsumed public binding keys")
	func rejectsUnconsumedBindingKeys() async throws {
		let fixture = try makeFixture()
		let service = try makeService(
			issuerURL: fixture.issuerURL,
			trustedRoots: try trustedRoots()
		)

		await #expect(throws: (any Error).self) {
			try await service.validateIssuedDocuments(
				fixture.document,
				batch: nil,
				publicKeys: [fixture.publicKey, fixture.publicKey]
			)
		}
	}

	@Test("Multiple cnf binding keys are removed using current indices")
	func consumesMultipleBindingKeys() throws {
		let keyA = CoseKey(x: Array(repeating: 1, count: 32), y: Array(repeating: 2, count: 32), crv: .P256)
		let keyB = CoseKey(x: Array(repeating: 3, count: 32), y: Array(repeating: 4, count: 32), crv: .P256)
		let jwks: [[String: String]] = [keyA, keyB].map { key in
			[
				"kty": "EC",
				"crv": "P-256",
				"x": Data(key.x).base64URLEncodedString(),
				"y": Data(key.y).base64URLEncodedString()
			]
		}
		let payload = try JSONSerialization.data(withJSONObject: ["cnf": ["jwk": jwks]])
		let serialized = "e30.\(payload.base64URLEncodedString()).signature"
		var publicKeys = [keyA, keyB]

		try OpenId4VciService.validateSdJwtBindingKeys(serialized, publicCoseKeys: &publicKeys)

		#expect(publicKeys.isEmpty)
	}

	private func makeService(
		issuerURL: String,
		trustedRoots: [x5chain]?,
		identityValidation: IssuerCertificateIdentityValidation = .whenPresent
	) throws -> OpenId4VciService {
		let storageService = TestDataStorageService()
		let storage = StorageManager(storageService: storageService)
		let config = OpenId4VciConfiguration(
			credentialIssuerURL: issuerURL,
			parUsage: .required(authorizationCodeDPoPBinding: true),
			requireDpop: true,
			trustedIssuerCertificates: trustedRoots,
			issuerCertificateIdentityValidation: identityValidation
		)
		return try OpenId4VciService(
			uiCulture: nil,
			config: config,
			networking: TestNetworking(metadata: Data()),
			storage: storage,
			storageService: storageService
		)
	}

	private func trustedRoots() throws -> [x5chain] {
		let data = try #require(Data(name: "pidissuerca02_ut", ext: "der", from: Bundle.module))
		let certificate = try #require(SecCertificateCreateWithData(nil, data as CFData))
		return [[certificate]]
	}

	private func makeFixture() throws -> (document: WalletStorage.Document, publicKey: Data, issuerURL: String) {
		let credential = try #require(Data(name: "sjwt-pid-python", ext: "txt", from: Bundle.module))
		let serialized = try #require(String(data: credential, encoding: .utf8))
		let (_, payload, _) = SdJwtUtils.extractJWTParts(serialized)
		let payloadData = try #require(Data(base64URLEncoded: payload))
		let payloadJson = try JSON(data: payloadData)
		let jwk = payloadJson["cnf"]["jwk"]
		let xString = try #require(jwk["x"].string)
		let yString = try #require(jwk["y"].string)
		let x = try #require(Data(base64URLEncoded: xString))
		let y = try #require(Data(base64URLEncoded: yString))
		let key = CoseKey(x: [UInt8](x), y: [UInt8](y), crv: .P256)
		let issuerURL = try #require(payloadJson["iss"].string)
		let document = WalletStorage.Document(
			id: UUID().uuidString,
			docType: "urn:eu:europa:ec:eudi:pid:1",
			docDataFormat: .sdjwt,
			data: credential,
			docKeyInfo: nil,
			createdAt: .now,
			metadata: nil,
			displayName: nil,
			status: .issued
		)
		return (document, Data(key.encode(options: CBOROptions())), issuerURL)
	}
}
