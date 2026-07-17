import Foundation
import MdocDataModel18013
import Testing
import WalletStorage
@testable import EudiWalletKit

@Suite("Storage manager safety tests")
@MainActor
struct StorageManagerSafetyTests {
	@Test("Negative document indexes fail safely")
	func negativeDocumentIndex() {
		let manager = StorageManager(storageService: CoordinatedStorageService(documents: [:]))
		#expect(manager.getDocumentModel(index: -1) == nil)
	}

	@Test("A persisted document can be deleted before published models are loaded")
	func coldDelete() async throws {
		let document = makeDocument(id: "cold", status: .pending)
		let store = CoordinatedStorageService(documents: [.pending: [document]])
		let manager = StorageManager(storageService: store)

		try await manager.deleteDocument(id: document.id, status: .pending)

		#expect(await store.document(id: document.id, status: .pending) == nil)
	}

	@Test("Placeholder existence does not require loading a credential key batch")
	func placeholderExistenceUsesStatusCollection() async throws {
		let document = makeDocument(id: "placeholder", status: .pending)
		let store = CoordinatedStorageService(
			documents: [.pending: [document]],
			singleLoadReturnsNil: true
		)
		let manager = StorageManager(storageService: store)
		let service = try OpenId4VciService(
			uiCulture: nil,
			config: OpenId4VciConfiguration(credentialIssuerURL: "https://issuer.example"),
			networking: TestNetworking(metadata: Data()),
			storage: manager,
			storageService: store
		)

		#expect(try await service.hasStoredDocument(id: document.id, status: .pending))
		try await manager.removePendingOrDeferredDoc(id: document.id)
		#expect(await store.document(id: document.id, status: .pending) == nil)
	}

	@Test("A nil storage load clears stale published state")
	func nilLoadClearsState() async throws {
		let document = makeDocument(id: "pending", status: .pending)
		let store = CoordinatedStorageService(documents: [.pending: [document]])
		let manager = StorageManager(storageService: store)
		_ = try await manager.loadDocuments(status: .pending, uiCulture: nil)
		#expect(manager.pendingDocuments.map(\.id) == [document.id])

		await store.returnNil(for: .pending)
		let result = try await manager.loadDocuments(status: .pending, uiCulture: nil)

		#expect(result == nil)
		#expect(manager.pendingDocuments.isEmpty)
		#expect(!manager.hasData)
	}

	@Test("Concurrent deletions re-find documents by identifier")
	func concurrentDeletion() async throws {
		let first = makeDocument(id: "first", status: .pending)
		let second = makeDocument(id: "second", status: .pending)
		let store = CoordinatedStorageService(
			documents: [.pending: [first, second]],
			coordinateDeleteCount: 2
		)
		let manager = StorageManager(storageService: store)
		_ = try await manager.loadDocuments(status: .pending, uiCulture: nil)

		async let deleteFirst: Void = manager.deleteDocument(id: first.id, status: .pending)
		async let deleteSecond: Void = manager.deleteDocument(id: second.id, status: .pending)
		_ = try await (deleteFirst, deleteSecond)

		#expect(manager.pendingDocuments.isEmpty)
	}

	private func makeDocument(id: String, status: DocumentStatus) -> WalletStorage.Document {
		WalletStorage.Document(
			id: id,
			docType: "test",
			docDataFormat: .sdjwt,
			data: Data("credential".utf8),
			docKeyInfo: nil,
			createdAt: .now,
			metadata: nil,
			displayName: nil,
			status: status
		)
	}
}

private actor CoordinatedStorageService: DataStorageService {
	private var documents: [DocumentStatus: [WalletStorage.Document]]
	private var nilStatuses: Set<DocumentStatus> = []
	private let coordinateDeleteCount: Int
	private let singleLoadReturnsNil: Bool
	private var deleteWaiters: [CheckedContinuation<Void, Never>] = []

	init(
		documents: [DocumentStatus: [WalletStorage.Document]],
		coordinateDeleteCount: Int = 0,
		singleLoadReturnsNil: Bool = false
	) {
		self.documents = documents
		self.coordinateDeleteCount = coordinateDeleteCount
		self.singleLoadReturnsNil = singleLoadReturnsNil
	}

	func returnNil(for status: DocumentStatus) {
		nilStatuses.insert(status)
	}

	func document(id: String, status: DocumentStatus) -> WalletStorage.Document? {
		documents[status]?.first { $0.id == id }
	}

	func loadDocument(id: String, status: DocumentStatus) async throws -> WalletStorage.Document? {
		singleLoadReturnsNil ? nil : document(id: id, status: status)
	}

	func loadDocumentMetadata(id: String, status: DocumentStatus) async throws -> DocMetadata? { nil }

	func loadDocuments(status: DocumentStatus) async throws -> [WalletStorage.Document]? {
		nilStatuses.contains(status) ? nil : (documents[status] ?? [])
	}

	func saveDocument(_ document: WalletStorage.Document, batch: [WalletStorage.Document]?, allowOverwrite: Bool) async throws {
		documents[document.status, default: []].removeAll { $0.id == document.id }
		documents[document.status, default: []].append(document)
	}

	func deleteDocument(id: String, status: DocumentStatus) async throws {
		if coordinateDeleteCount > 0 {
			await withCheckedContinuation { continuation in
				deleteWaiters.append(continuation)
				if deleteWaiters.count == coordinateDeleteCount {
					let waiters = deleteWaiters
					deleteWaiters.removeAll()
					waiters.forEach { $0.resume() }
				}
			}
		}
		documents[status, default: []].removeAll { $0.id == id }
	}

	func deleteDocuments(status: DocumentStatus) async throws { documents[status] = [] }
	func deleteDocumentCredential(id: String, index: Int) async throws {}
}
