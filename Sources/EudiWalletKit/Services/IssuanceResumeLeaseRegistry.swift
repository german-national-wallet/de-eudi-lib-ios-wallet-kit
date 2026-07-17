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
import WalletStorage

/// Coordinates placeholder consumption across service actors that share the
/// same storage actor. This registry stores no wallet data or dependencies; it
/// only owns short-lived identity keys while a resume operation is active.
final class IssuanceResumeLeaseRegistry: @unchecked Sendable {
	static let shared = IssuanceResumeLeaseRegistry()

	private struct Lease: Hashable {
		let storage: ObjectIdentifier
		let documentId: String
	}

	private let lock = NSLock()
	private var activeLeases: Set<Lease> = []

	private init() {}

	func acquire(storage: any DataStorageService, documentId: String) throws {
		let lease = Lease(storage: ObjectIdentifier(storage), documentId: documentId)
		let inserted = lock.withLock { activeLeases.insert(lease).inserted }
		guard inserted else {
			throw PresentationSession.makeError(str: "An issuance resume is already in progress for this document")
		}
	}

	func release(storage: any DataStorageService, documentId: String) {
		let lease = Lease(storage: ObjectIdentifier(storage), documentId: documentId)
		lock.withLock { _ = activeLeases.remove(lease) }
	}
}
