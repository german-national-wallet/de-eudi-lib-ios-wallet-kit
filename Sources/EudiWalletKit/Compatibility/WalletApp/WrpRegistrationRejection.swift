import Foundation
import OpenID4VP

/// Why the wallet refused a presentation request on registration-certificate grounds.
///
/// Only covers failures that arrive as a *thrown* error. Over-asking is not one of them: it is
/// reported as a warning and is found through ``Swift/Collection/containsOverAskedClaims`` instead.
public enum WrpRegistrationRejection: Sendable, Equatable {
	/// No usable registration certificate accompanied the request, so there is nothing to check the
	/// request against. Covers a missing `verifier_info`, a missing WRPRC entry within it, a client
	/// without an access certificate (WRPAC), and more than one WRPRC.
	case certificateMissing
}

public extension WalletError {
	/// The registration-certificate rejection this error represents, or `nil` if it is an unrelated
	/// failure.
	///
	/// `OpenId4VpService.receiveRequest` collapses every request-resolution failure onto
	/// ``WalletError/Code/invalidQueryResolution`` (or `.trustError`), and the OpenID4VP library
	/// reports the reason only as free text on `ValidationError.validationError`. So a WRPRC
	/// rejection cannot be told apart from a malformed request by code alone. Classifying it here
	/// keeps that inspection in one place rather than spreading string matching across callers.
	var wrpRegistrationRejection: WrpRegistrationRejection? {
		guard code == .invalidQueryResolution || code == .trustError || code == .invalidWrprc else {
			return nil
		}
		// The library raises all of these from `RequestAuthenticator.validateRegistrationCertificateIfNeeded`,
		// and each message names the artefact that was missing or unusable.
		let haystack = [(innerError as? ValidationError)?.errorDescription, innerError?.localizedDescription, description]
			.compactMap { $0 }
			.joined(separator: " ")
		guard haystack.contains("WRPRC") || haystack.contains("WRPAC") else { return nil }
		return .certificateMissing
	}
}

public extension Collection<PresentationPolicyViolation> {
	/// The over-asking violations in this collection.
	///
	/// wallet-kit never blocks a presentation for over-asking — ``PresentationFailureReason``'s
	/// enforceable set deliberately excludes it, so it always arrives as a warning. A wallet that
	/// wants to refuse the request decides that for itself, and this is the predicate to decide on.
	var overAskedClaimViolations: [PresentationPolicyViolation] {
		filter { violation in
			if case .overAskedClaims = violation.reason { return true }
			return false
		}
	}

	/// Whether the relying party asked for anything beyond its registration certificate's scope.
	var containsOverAskedClaims: Bool {
		!overAskedClaimViolations.isEmpty
	}
}

public extension PresentationSession {
	/// Every registration-certificate violation raised for this request.
	///
	/// Violations arrive in two places and the wallet-kit documentation says to consult both: the
	/// request-wide entries in ``wrpVerifierWarnings`` (whose empty key holds those not tied to a
	/// particular credential query) and the per-option entries attached to each
	/// ``DisclosedDocumentSet``. Duplicates are dropped while preserving order.
	var allPolicyViolations: [PresentationPolicyViolation] {
		let requestWide = wrpVerifierWarnings?.values.flatMap { $0 } ?? []
		let perOption = disclosedDocumentSets.compactMap(\.warnings).flatMap { $0 }
		var seen = Set<PresentationPolicyViolation>()
		return (requestWide + perOption).filter { seen.insert($0).inserted }
	}
}
