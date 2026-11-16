import Testing
import Foundation
import CryptoKit
import MdocDataModel18013
@testable import EudiWalletKit

@Suite("DPoP key creation options")
struct DPoPKeyCreationOptionsTests {

	@Test func newKey_IsTaggedWithTheAuthorizationServerNonce() async throws {
		let base = KeyOptions(curve: .P256, secureAreaName: "UnregisteredTestArea")

		let options = await OpenId4VciService.dpopKeyOptions(base, keyId: "dpop-new", authorizationServerNonce: "as-nonce")

		let tag = try #require(DPoPKeyCreationOptions.decode(options?.additionalOptions))
		#expect(tag.authorizationServerNonce == "as-nonce")
		#expect(options?.secureAreaName == "UnregisteredTestArea")
	}

	@Test func missingKeyWithoutNonce_IsTaggedWithoutNonce() async throws {
		SecureAreaRegistry.shared.register(secureArea: StoredKeyInfoSecureArea(keyInfos: [:]))
		let base = KeyOptions(curve: .P256, secureAreaName: StoredKeyInfoSecureArea.name)

		let options = await OpenId4VciService.dpopKeyOptions(base, keyId: "dpop-missing", authorizationServerNonce: nil)

		let tag = try #require(DPoPKeyCreationOptions.decode(options?.additionalOptions))
		#expect(tag.authorizationServerNonce == nil)
	}

	@Test func existingKeyWithoutNonce_ReusesItsStoredOptions() async throws {
		let keyId = "dpop-existing"
		let stored = KeyOptions(curve: .P256, secureAreaName: StoredExistingKeySecureArea.name, additionalOptions: Data("legacy".utf8))
		SecureAreaRegistry.shared.register(secureArea: StoredExistingKeySecureArea(keyInfos: [keyId: KeyBatchInfo(keyOptions: stored, usedCounts: [0], credentialPolicy: .rotateUse)]))

		let options = await OpenId4VciService.dpopKeyOptions(KeyOptions(curve: .P256, secureAreaName: StoredExistingKeySecureArea.name), keyId: keyId, authorizationServerNonce: nil)

		#expect(options == stored)
	}

	@Test func noBaseOptions_StayNil() async {
		#expect(await OpenId4VciService.dpopKeyOptions(nil, keyId: "dpop-none", authorizationServerNonce: "as-nonce") == nil)
	}

	@Test func decode_RejectsOtherAdditionalOptions() {
		#expect(DPoPKeyCreationOptions.decode(nil) == nil)
		#expect(DPoPKeyCreationOptions.decode(Data("eu.europa.ec.eudi.pid.1".utf8)) == nil)
		#expect(DPoPKeyCreationOptions.decode(Data(#"{"purpose":"credential","authorization_server_nonce":"x"}"#.utf8)) == nil)
	}
}

/// Answers `getKeyBatchInfo` from a fixed table. Each tag gives it its own registry name, so parallel
/// tests don't replace each other's instance. Every other requirement is unreachable in these tests.
private actor FixedKeyInfoSecureArea<Tag: FixedKeyInfoTag>: SecureArea {
	static var name: String { Tag.name }
	static var defaultEcCurve: CoseEcCurve { .P256 }
	static var supportedEcCurves: [CoseEcCurve] { [.P256] }

	private let keyInfos: [String: KeyBatchInfo]

	init(keyInfos: [String: KeyBatchInfo]) { self.keyInfos = keyInfos }

	nonisolated static func create(storage: any SecureKeyStorage) -> FixedKeyInfoSecureArea<Tag> { FixedKeyInfoSecureArea(keyInfos: [:]) }

	func getKeyBatchInfo(id: String) async throws -> KeyBatchInfo {
		guard let info = keyInfos[id] else { throw Unreachable() }
		return info
	}

	func getStorage() async -> any SecureKeyStorage { NoopStorage() }
	nonisolated func defaultSigningAlgorithm(ecCurve: CoseEcCurve) -> SigningAlgorithm { .ES256 }
	func unlockKey(id: String) async throws -> Data? { nil }
	func createKeyBatch(id: String, credentialOptions: CredentialOptions, keyOptions: KeyOptions?) async throws -> [CoseKey] { throw Unreachable() }
	func deleteKeyBatch(id: String, startIndex: Int, batchSize: Int) async throws { throw Unreachable() }
	func deleteKeyInfo(id: String) async throws { throw Unreachable() }
	func getPublicKey(id: String, index: Int, curve: CoseEcCurve) async throws -> CoseKey { throw Unreachable() }
	func getInfoAndCurve(id: String) async throws -> ([String: Data], CoseEcCurve) { throw Unreachable() }
	func signature(id: String, index: Int, algorithm: SigningAlgorithm, dataToSign: Data, unlockData: Data?, authenticationContext: ThreadSafeAuthContext) async throws -> Data { throw Unreachable() }
	func keyAgreement(id: String, index: Int, publicKey: CoseKey, unlockData: Data?, authenticationContext: ThreadSafeAuthContext) async throws -> SharedSecret { throw Unreachable() }

	struct Unreachable: Error {}
}

private protocol FixedKeyInfoTag { static var name: String { get } }
private enum MissingKeyTag: FixedKeyInfoTag { static var name: String { "DPoPKeyCreationOptionsTests.Missing" } }
private enum ExistingKeyTag: FixedKeyInfoTag { static var name: String { "DPoPKeyCreationOptionsTests.Existing" } }
private typealias StoredKeyInfoSecureArea = FixedKeyInfoSecureArea<MissingKeyTag>
private typealias StoredExistingKeySecureArea = FixedKeyInfoSecureArea<ExistingKeyTag>

private actor NoopStorage: SecureKeyStorage {
	func readKeyInfo(id: String) throws -> [String: Data] { [:] }
	func readKeyData(id: String, index: Int, authenticationContext: ThreadSafeAuthContext) throws -> [String: Data] { [:] }
	func writeKeyInfo(id: String, dict: [String: Data]) throws {}
	func writeKeyDataBatch(id: String, startIndex: Int, dicts: [[String: Data]], keyOptions: KeyOptions?) async throws {}
	func deleteKeyBatch(id: String, startIndex: Int, batchSize: Int) throws {}
	func deleteKeyInfo(id: String) throws {}
}
